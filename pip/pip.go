package pip

import (
	"strings"
	"github.com/senseyeio/diligent"
	"bufio"
	"fmt"
	"io/ioutil"
)


type pkg struct {
	Path     string `json:"path"`
	Revision string `json:"revision"`
}


type pip struct{}

func New() diligent.Deper {
	return &pip{}
}

func Any(vs []string, f func(string) bool) bool {
	for _, v := range vs {
		if f(v) {
			return true
		}
	}
	return false
}

func (p *pip) IsCompatible(filename string, fileContents []byte) bool {
	return strings.Index(filename, "requirements.txt") != -1
}

func (p *pip) readRequirementLine(line string) pkg {
	return pkg{Path:line,Revision:"unset"}
}

func (p *pip) readRequirements(file []byte) []pkg {
	requirements := make([]pkg, 0)

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
		} else if Any([]string{"-f", "--find-links", "-i", "--index-url", "--extra-index-url", "--no-index",}, func(s string) bool {
			return strings.Index(line, s) == 0
			}) {
			continue
		} else {
			if Any([]string{"-e","--editable",}, func(s string) bool { return strings.Index(line,s) == 0}) {
				continue
			} else {
				requirements = append(requirements, p.readRequirementLine(line))
			}
		}
	}
	return requirements
}

func (p *pip) Dependencies(file []byte) ([]diligent.Dep, error) {
	deps := make([]diligent.Dep, 0)
	fmt.Println(p.readRequirements(file))
	return deps, nil
}

func (p *pip) Name() string {
	return "pip"
}