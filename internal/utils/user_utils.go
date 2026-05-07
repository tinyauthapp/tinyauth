package utils

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/tinyauthapp/tinyauth/internal/model"
)

func ParseUsers(usersStr []string, userAttributes map[string]model.UserAttributes) (*[]model.LocalUser, error) {
	var users []model.LocalUser

	if len(usersStr) == 0 {
		return nil, nil
	}

	for _, user := range usersStr {
		if strings.TrimSpace(user) == "" {
			continue
		}
		parsed, err := ParseUser(strings.TrimSpace(user))
		if err != nil {
			return nil, err
		}
		if attrs, ok := userAttributes[parsed.Username]; ok {
			parsed.Attributes = attrs
		}
		users = append(users, *parsed)
	}

	return &users, nil
}

func GetUsers(usersCfg []string, usersPath string, userAttributes map[string]model.UserAttributes) (*[]model.LocalUser, error) {
	usersStr, err := GetStringList(usersCfg, usersPath)
	if err != nil {
		return nil, err
	}

	return ParseUsers(usersStr, userAttributes)
}

func ParseUser(userStr string) (*model.LocalUser, error) {
	if strings.Contains(userStr, "$$") {
		userStr = strings.ReplaceAll(userStr, "$$", "$")
	}

	parts := strings.SplitN(userStr, ":", 4)

	if len(parts) < 2 || len(parts) > 3 {
		return nil, errors.New("invalid user format")
	}

	for i, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			return nil, errors.New("invalid user format")
		}
		parts[i] = trimmed
	}

	user := model.LocalUser{
		Username: parts[0],
		Password: parts[1],
	}

	if len(parts) == 3 {
		user.TOTPSecret = parts[2]
	}

	return &user, nil
}

func CompileUserEmail(username string, domain string) string {
	_, err := mail.ParseAddress(username)

	if err != nil {
		return fmt.Sprintf("%s@%s", strings.ToLower(username), domain)
	}

	return username
}
