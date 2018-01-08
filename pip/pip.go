package pip

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/senseyeio/diligent"
	"io/ioutil"
	"regexp"
	"strings"
)

type pkg struct {
	Path     string `json:"path"`
	Revision string `json:"revision"`
}

type Requirement struct {
	Line         string
	VCS          string
	URI          string
	Revision     string
	Name         string
	Extras       []string
	HashName     string
	Hash         string
	Subdirectory string
	LocalFile    bool
	Editable     bool
	Path         string
}

type pip struct {
	UriRegex       *regexp.Regexp
	VcsRegex       *regexp.Regexp
	LocalRegex     *regexp.Regexp
	ExtrasRegex    *regexp.Regexp
	HashAlgorithms []string
	VCSSchemes     []string
	VCS            []string
}

const UriRegexString = `^(?P<scheme>https?|file|ftps?)://(?P<path>[^#]+)(#(?P<fragment>\S+))?`
const VcsRegexString = `^(?P<scheme>%s)://((?P<login>[^/@]+)@)?(?P<path>[^#@]+)(@(?P<revision>[^#]+))?(#(?P<fragment>\S+))?`
const LocalRegexString = `^((?P<scheme>file)://)?(?P<path>[^#]+)(#(?P<fragment>\S+))?`
const ExtrasRegexString = `(?P<name>.+)\[(?P<extras>[^\]]+)\]`

func New() diligent.Deper {
	var vcsSchemes = []string{"git", "git+https", "git+ssh", "git+git", "hg+http", "hg+https", "hg+static-http", "hg+ssh", "svn", "svn+svn", "svn+http", "svn+https", "svn+ssh", "bzr+http", "bzr+https", "bzr+ssh", "bzr+sftp", "bzr+ftp", "bzr+lp"}
	schemesRegExString := strings.Replace(strings.Join(vcsSchemes, "|"), "+", "\\+", -1)

	return &pip{
		UriRegex:       regexp.MustCompile(UriRegexString),
		VcsRegex:       regexp.MustCompile(fmt.Sprintf(VcsRegexString, schemesRegExString)),
		LocalRegex:     regexp.MustCompile(LocalRegexString),
		ExtrasRegex:    regexp.MustCompile(ExtrasRegexString),
		HashAlgorithms: []string{"sha1", "sha224", "sha384", "sha256", "sha512", "md5"},
		VCSSchemes:     vcsSchemes,
		VCS:            []string{"git", "hg", "svn", "bzr"},
	}
}

func Any(vs []string, f func(string) bool) bool {
	for _, v := range vs {
		if f(v) {
			return true
		}
	}
	return false
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func (p *pip) IsCompatible(filename string, fileContents []byte) bool {
	return strings.Index(filename, "requirements.txt") != -1
}

func matchToMap(r *regexp.Regexp, s string) map[string]string {
	match := r.FindStringSubmatch(s)
	result := make(map[string]string)
	if match == nil || len(match) == 0 {
		return result
	}
	for i, name := range r.SubexpNames() {
		if i != 0 {
			result[name] = match[i]
		}
	}
	return result
}

func (p *pip) parseFragment(fragment string) (map[string]string, error) {
	fragment = strings.TrimLeft(fragment, "#")
	result := make(map[string]string)

	pairs := strings.Split(fragment, "&")
	if len(pairs) == 0 {
		return nil, errors.New("invalid fragment string")
	}

	for _, pair := range pairs {
		splitPair := strings.Split(pair, "=")
		if len(splitPair) != 2 {
			return nil, errors.New("invalid pair")
		}
		result[splitPair[0]] = splitPair[1]
	}

	return result, nil
}

func (p *pip) parseExtras(egg string) (string, []string) {
	eggMatches := matchToMap(p.ExtrasRegex, egg)
	if len(eggMatches) > 0 {
		return eggMatches["name"], strings.Split(eggMatches["extras"], ",")
	}
	return egg, make([]string, 0)
}

func (p *pip) parseHash(fragment map[string]string) (string, string, bool) {
	for key, val := range fragment {
		if stringInSlice(strings.ToLower(key), p.HashAlgorithms) {
			return key, val, true
		}
	}
	return "", "", false
}

func (p *pip) readEditableRequirementLine(line string) (Requirement, error) {
	// Chop off the -e
	line = strings.Replace(line, "-e ", "", 1)
	line = strings.Replace(line, "--editable ", "", 1)
	requirement := Requirement{Line: line}
	requirement.Editable = true

	vcsMatch := matchToMap(p.VcsRegex, line)
	localMatch := matchToMap(p.LocalRegex, line)

	if len(vcsMatch) > 0 {
		if login, ok := vcsMatch["login"]; ok {
			requirement.URI = fmt.Sprintf("%s://%s@%s}", vcsMatch["scheme"], login, vcsMatch["path"])
		} else {
			requirement.URI = fmt.Sprintf("%s://%s}", vcsMatch["scheme"], vcsMatch["path"])
		}
		requirement.Revision = vcsMatch["revision"]
		if fragmentString, ok := vcsMatch["fragment"]; ok {
			fragment, err := p.parseFragment(fragmentString)
			if err != nil {
				return requirement, err
			}

			egg := fragment["egg"]

			requirement.Name, requirement.Extras = p.parseExtras(egg)

			if hashName, hash, found := p.parseHash(fragment); found {
				requirement.HashName, requirement.Hash = hashName, hash
			}
			requirement.Subdirectory = fragment["subdirectory"]

		}

		for _, vcs := range p.VCS {
			if strings.HasPrefix(requirement.URI, vcs) {
				requirement.VCS = vcs
			}
		}

	} else if len(localMatch) > 0 {
		requirement.LocalFile = true
		if fragmentString, ok := localMatch["fragment"]; ok {
			fragment, err := p.parseFragment(fragmentString)
			if err != nil {
				return requirement, err
			}

			egg := fragment["egg"]

			requirement.Name, requirement.Extras = p.parseExtras(egg)

			if hashName, hash, found := p.parseHash(fragment); found {
				requirement.HashName, requirement.Hash = hashName, hash
			}
			requirement.Subdirectory = fragment["subdirectory"]
		}
		requirement.Path = localMatch["path"]

	} else {
		return requirement, errors.New("invalid editable line")
	}

	return requirement, nil

}

func (p *pip) readStaticRequirementLine(line string) (Requirement, error) {
	requirement := Requirement{Line: line}
	vcsMatch := matchToMap(p.VcsRegex, line)
	uriMatch := matchToMap(p.UriRegex, line)
	localMatch := matchToMap(p.LocalRegex, line)

	if len(vcsMatch) > 0 {
		if login, ok := vcsMatch["login"]; ok {
			requirement.URI = fmt.Sprintf("%s://%s@%s}", vcsMatch["scheme"], login, vcsMatch["path"])
		} else {
			requirement.URI = fmt.Sprintf("%s://%s}", vcsMatch["scheme"], vcsMatch["path"])
		}
		requirement.Revision = vcsMatch["revision"]
		if fragmentString, ok := vcsMatch["fragment"]; ok {
			fragment, err := p.parseFragment(fragmentString)
			if err != nil {
				return requirement, err
			}

			egg := fragment["egg"]

			requirement.Name, requirement.Extras = p.parseExtras(egg)

			if hashName, hash, found := p.parseHash(fragment); found {
				requirement.HashName, requirement.Hash = hashName, hash
			}
			requirement.Subdirectory = fragment["subdirectory"]

		}

	} else if len(uriMatch) > 0 {
		requirement.URI = fmt.Sprintf("%s://%s}", uriMatch["scheme"], uriMatch["path"])

		if fragmentString, ok := uriMatch["fragment"]; ok {
			fragment, err := p.parseFragment(fragmentString)
			if err != nil {
				return requirement, err
			}

			egg := fragment["egg"]

			requirement.Name, requirement.Extras = p.parseExtras(egg)

			if hashName, hash, found := p.parseHash(fragment); found {
				requirement.HashName, requirement.Hash = hashName, hash
			}
			requirement.Subdirectory = fragment["subdirectory"]
		}

		if scheme, ok := uriMatch["scheme"]; ok && scheme == "file" {
			requirement.LocalFile = true
		}

	} else if strings.Index(line, "#egg=") != -1 {
		if len(localMatch) == 0 {
			return requirement, errors.New("local match should match everything")
		}
		requirement.LocalFile = true

		if fragmentString, ok := localMatch["fragment"]; ok {
			fragment, err := p.parseFragment(fragmentString)
			if err != nil {
				return requirement, err
			}

			egg := fragment["egg"]

			requirement.Name, requirement.Extras = p.parseExtras(egg)

			if hashName, hash, found := p.parseHash(fragment); found {
				requirement.HashName, requirement.Hash = hashName, hash
			}
			requirement.Subdirectory = fragment["subdirectory"]
		}

		requirement.Path = localMatch["path"]
	} else {
		// TODO: Temporary. Look at pip library for better handling.
		pieces := strings.Split(line, "==")
		if len(pieces) != 2 {
			return requirement, errors.New("not handled yet")
		}
		requirement.Name = pieces[0]
		requirement.Revision = pieces[1]
	}
	return requirement, nil
}

func (p *pip) readRequirements(file []byte) []Requirement {
	requirements := make([]Requirement, 0)

	scanner := bufio.NewScanner(strings.NewReader(string(file)))
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.Index(line, "#") == 0 {
			continue
		} else if strings.Index(line, "-r") == 0 || strings.Index(line, "--requirement") == 0 {
			pieces := strings.Fields(line)
			// TODO: Very much untested
			fileBytes, err := ioutil.ReadFile(pieces[1])
			if err != nil {
				fmt.Println("Skipping requirements")
				continue
			}
			requirements = append(requirements, p.readRequirements(fileBytes)...)
			continue
		} else if Any([]string{"-f", "--find-links", "-i", "--index-url", "--extra-index-url", "--no-index"}, func(s string) bool {
			return strings.Index(line, s) == 0
		}) {
			continue
		} else {
			if Any([]string{"-e", "--editable"}, func(s string) bool { return strings.Index(line, s) == 0 }) {
				// Parse editable requirement
				editableRequirement, error := p.readEditableRequirementLine(line)
				if error == nil {
					requirements = append(requirements, editableRequirement)
				}
				continue
			} else {
				// Parse static requirement
				staticRequirement, error := p.readStaticRequirementLine(line)
				if error == nil {
					requirements = append(requirements, staticRequirement)
				}
			}
		}
	}
	return requirements
}

func (p *pip) Dependencies(file []byte) ([]diligent.Dep, error) {
	deps := make([]diligent.Dep, 0)
	for _, requirement := range p.readRequirements(file) {
		deps = append(deps, diligent.Dep{Name: requirement.Name})
	}
	fmt.Println(deps)
	return deps, nil
}

func (p *pip) Name() string {
	return "pip"
}
