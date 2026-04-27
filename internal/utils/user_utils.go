package utils

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/tinyauthapp/tinyauth/internal/config"
)

func ParseUsers(usersStr []string, userAttributes map[string]config.UserAttributes) ([]config.User, error) {
	var users []config.User

	if len(usersStr) == 0 {
		return []config.User{}, nil
	}

	for _, user := range usersStr {
		if strings.TrimSpace(user) == "" {
			continue
		}
		parsed, err := ParseUser(strings.TrimSpace(user))
		if err != nil {
			return []config.User{}, err
		}
		if attrs, ok := userAttributes[parsed.Username]; ok {
			parsed.Attributes = attrs
		}
		users = append(users, parsed)
	}

	return users, nil
}

func GetUsers(usersCfg []string, usersPath string, userAttributes map[string]config.UserAttributes) ([]config.User, error) {
	var usersStr []string

	if len(usersCfg) == 0 && usersPath == "" {
		return []config.User{}, nil
	}

	if len(usersCfg) > 0 {
		usersStr = append(usersStr, usersCfg...)
	}

	if usersPath != "" {
		contents, err := ReadFile(usersPath)

		if err != nil {
			return []config.User{}, err
		}

		lines := strings.SplitSeq(contents, "\n")

		for line := range lines {
			lineTrimmed := strings.TrimSpace(line)
			if lineTrimmed == "" {
				continue
			}
			usersStr = append(usersStr, lineTrimmed)
		}
	}

	return ParseUsers(usersStr, userAttributes)
}

func ParseUser(userStr string) (config.User, error) {
	if strings.Contains(userStr, "$$") {
		userStr = strings.ReplaceAll(userStr, "$$", "$")
	}

	parts := strings.SplitN(userStr, ":", 4)

	if len(parts) < 2 || len(parts) > 3 {
		return config.User{}, errors.New("invalid user format")
	}

	for i, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			return config.User{}, errors.New("invalid user format")
		}
		parts[i] = trimmed
	}

	user := config.User{
		Username: parts[0],
		Password: parts[1],
	}

	if len(parts) == 3 {
		user.TotpSecret = parts[2]
	}

	return user, nil
}

func CompileUserEmail(username string, domain string) string {
	_, err := mail.ParseAddress(username)

	if err != nil {
		return fmt.Sprintf("%s@%s", strings.ToLower(username), domain)
	}

	return username
}
