package utils

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"golang.org/x/crypto/bcrypt"
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
		// Validation lives here, at config load, rather than in ParseUser, which the verify and
		// generate-totp commands call directly on an already-stored hash.
		if !isBcryptHash(parsed.Password) {
			return nil, fmt.Errorf("invalid password hash for user %q, expected a single bcrypt hash", parsed.Username)
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

// bcryptBase64Alphabet is the (non-standard) base64 alphabet bcrypt encodes its salt and hash with.
const bcryptBase64Alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// isBcryptHash reports whether s is exactly one canonical bcrypt hash. bcrypt ignores trailing bytes and
// parses the cost leniently, and bcrypt.CompareHashAndPassword re-encodes a hash before comparing, so a
// value that merely looks close (wrong delimiter, non-canonical base64 tail bits, trailing garbage) would
// pass a loose check yet never authenticate. The full layout is validated to reject those:
//
//	$ 2[aby] $ <2-digit cost> $ <22-char salt> <31-char hash>   (60 bytes)
func isBcryptHash(s string) bool {
	if len(s) != 60 {
		return false
	}

	// Prefix: "$2[aby]$NN$" where NN is the two-digit cost.
	if s[0] != '$' || s[1] != '2' || (s[2] != 'a' && s[2] != 'b' && s[2] != 'y') || s[3] != '$' || s[6] != '$' {
		return false
	}
	if s[4] < '0' || s[4] > '9' || s[5] < '0' || s[5] > '9' {
		return false
	}
	if cost := int(s[4]-'0')*10 + int(s[5]-'0'); cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return false
	}

	// The 22-char salt and 31-char hash must be in the bcrypt base64 alphabet.
	for i := 7; i < len(s); i++ {
		if strings.IndexByte(bcryptBase64Alphabet, s[i]) < 0 {
			return false
		}
	}

	// 22 base64 chars hold the 16-byte salt (4 excess bits) and 31 hold the 23-byte hash (2 excess bits),
	// so the final char of each must carry zero in those excess low bits. Otherwise bcrypt re-encodes it
	// to a different canonical string and a password can never match the stored value.
	if strings.IndexByte(bcryptBase64Alphabet, s[28])%16 != 0 {
		return false
	}
	if strings.IndexByte(bcryptBase64Alphabet, s[59])%4 != 0 {
		return false
	}

	return true
}

func CompileUserEmail(username string, domain string) string {
	_, err := mail.ParseAddress(username)

	if err != nil {
		return fmt.Sprintf("%s@%s", strings.ToLower(username), domain)
	}

	return username
}
