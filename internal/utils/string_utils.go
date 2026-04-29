package utils

import (
	"strings"
)

func Capitalize(str string) string {
	if len(str) == 0 {
		return ""
	}
	return strings.ToUpper(string([]rune(str)[0])) + string([]rune(str)[1:])
}

func CoalesceToString(value any) string {
	switch v := value.(type) {
	case []any:
		strs := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				strs = append(strs, str)
				continue
			}
		}
		return strings.Join(strs, ",")
	case string:
		return v
	default:
		return ""
	}
}

func ParseNonEmptyLines(contents string) []string {
	lines := make([]string, 0)

	for line := range strings.SplitSeq(contents, "\n") {
		lineTrimmed := strings.TrimSpace(line)
		if lineTrimmed == "" {
			continue
		}
		lines = append(lines, lineTrimmed)
	}

	return lines
}

func GetStringList(valuesCfg []string, valuesPath string) ([]string, error) {
	values := make([]string, 0, len(valuesCfg))

	for _, value := range valuesCfg {
		valueTrimmed := strings.TrimSpace(value)
		if valueTrimmed == "" {
			continue
		}
		values = append(values, valueTrimmed)
	}

	if valuesPath == "" {
		return values, nil
	}

	contents, err := ReadFile(valuesPath)
	if err != nil {
		return []string{}, err
	}

	values = append(values, ParseNonEmptyLines(contents)...)
	return values, nil
}
