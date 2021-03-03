package tagparser

import (
	"regexp"
)

type Validation struct {
	Name   string
	Params []string
}

var (
	parseRegex      = regexp.MustCompile(`(([^:]+):"([^"]*)")([[:space:]]*)`)
	parseValidation = regexp.MustCompile(`([^,|=]+)(=('[^']*'|[^,|]+))?|[| ,]`)
	parseParams     = regexp.MustCompile(`'([^']*)'|([^ ]+)`)
)

func parseValidations(value string) []*Validation {
	matches := parseValidation.FindAllStringSubmatch(value, -1)
	if len(matches) == 0 {
		return nil
	}
	validations := make([]*Validation, 0)
	for matchIndex := 0; matchIndex < len(matches); matchIndex++ {
		match := matches[matchIndex]
		if match[0] == "," || match[0] == "|" {
			continue
		}
		validation := &Validation{
			Name: match[1],
		}
		if validation.Params == nil {
			validation.Params = make([]string, 0, 1)
		}
		matchesParams := parseParams.FindAllStringSubmatch(match[3], -1)

		for _, p := range matchesParams {
			if p[2] != "" {

				validation.Params = append(validation.Params, p[2])
				continue
			}
			validation.Params = append(validation.Params, p[1])
		}

		validations = append(validations, validation)
	}
	return validations
}

func Parse(tag string) []*Validation {
	matches := parseRegex.FindAllStringSubmatch(tag, -1)
	if len(matches) == 0 {
		return nil
	}
	for _, m := range matches {
		if m[2] == "validate" { // TODO(Jota): Make "validate" customizable.
			return parseValidations(m[3])
		}
	}
	return nil
}
