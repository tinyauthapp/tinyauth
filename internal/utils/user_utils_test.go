package utils_test

import (
	"os"
	"testing"

	"github.com/tinyauthapp/tinyauth/internal/config"
	"github.com/tinyauthapp/tinyauth/internal/utils"

	"gotest.tools/v3/assert"
)

func TestGetUsers(t *testing.T) {
	hash := "$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G"

	// Setup
	file, err := os.Create("/tmp/tinyauth_users_test.txt")
	assert.NilError(t, err)

	_, err = file.WriteString("      user1:" + hash + "        \n         user2:" + hash + "                    ") // Spacing is on purpose
	assert.NilError(t, err)

	err = file.Close()
	assert.NilError(t, err)
	defer os.Remove("/tmp/tinyauth_users_test.txt")

	noAttrs := map[string]config.UserAttributes{}

	// Test file only
	users, err := utils.GetUsers([]string{}, "/tmp/tinyauth_users_test.txt", noAttrs)

	assert.NilError(t, err)

	assert.Equal(t, 2, len(users))

	assert.Equal(t, "user1", users[0].Username)
	assert.Equal(t, hash, users[0].Password)
	assert.Equal(t, "user2", users[1].Username)
	assert.Equal(t, hash, users[1].Password)

	// Test inline config only
	users, err = utils.GetUsers([]string{"user3:" + hash, "user4:" + hash}, "", noAttrs)

	assert.NilError(t, err)

	assert.Equal(t, 2, len(users))
	assert.Equal(t, "user3", users[0].Username)
	assert.Equal(t, "user4", users[1].Username)

	// Test both
	users, err = utils.GetUsers([]string{"user5:" + hash}, "/tmp/tinyauth_users_test.txt", noAttrs)

	assert.NilError(t, err)

	assert.Equal(t, 3, len(users))

	usernames := map[string]bool{}
	for _, u := range users {
		usernames[u.Username] = true
	}
	assert.Assert(t, usernames["user1"])
	assert.Assert(t, usernames["user2"])
	assert.Assert(t, usernames["user5"])

	// Test attributes applied from userAttributes map
	attrs := map[string]config.UserAttributes{
		"user1": {Name: "User One", Email: "user1@example.com"},
	}
	users, err = utils.GetUsers([]string{}, "/tmp/tinyauth_users_test.txt", attrs)

	assert.NilError(t, err)
	assert.Equal(t, 2, len(users))

	for _, u := range users {
		if u.Username == "user1" {
			assert.Equal(t, "User One", u.Attributes.Name)
			assert.Equal(t, "user1@example.com", u.Attributes.Email)
		}
		if u.Username == "user2" {
			assert.Equal(t, "", u.Attributes.Name)
		}
	}

	// Test empty
	users, err = utils.GetUsers([]string{}, "", noAttrs)

	assert.NilError(t, err)

	assert.Equal(t, 0, len(users))

	// Test non-existent file
	users, err = utils.GetUsers([]string{}, "/tmp/non_existent_file.txt", noAttrs)

	assert.ErrorContains(t, err, "no such file or directory")

	assert.Equal(t, 0, len(users))
}

func TestParseUser(t *testing.T) {
	hash := "$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G"

	// Valid user without TOTP
	user, err := utils.ParseUser("user1:" + hash)

	assert.NilError(t, err)

	assert.Equal(t, "user1", user.Username)
	assert.Equal(t, hash, user.Password)
	assert.Equal(t, "", user.TotpSecret)

	// Valid user with TOTP
	user, err = utils.ParseUser("user2:" + hash + ":ABCDEF")

	assert.NilError(t, err)

	assert.Equal(t, "user2", user.Username)
	assert.Equal(t, hash, user.Password)
	assert.Equal(t, "ABCDEF", user.TotpSecret)

	// Valid user with $$ in password
	user, err = utils.ParseUser("user3:pa$$word123")

	assert.NilError(t, err)

	assert.Equal(t, "user3", user.Username)
	assert.Equal(t, "pa$word123", user.Password)
	assert.Equal(t, "", user.TotpSecret)

	// User with spaces
	user, err = utils.ParseUser("   user4   :   password123   :   TOTPSECRET   ")

	assert.NilError(t, err)

	assert.Equal(t, "user4", user.Username)
	assert.Equal(t, "password123", user.Password)
	assert.Equal(t, "TOTPSECRET", user.TotpSecret)

	// Invalid users
	_, err = utils.ParseUser("user1") // Missing password
	assert.ErrorContains(t, err, "invalid user format")

	_, err = utils.ParseUser("user1:")
	assert.ErrorContains(t, err, "invalid user format")

	_, err = utils.ParseUser(":password123")
	assert.ErrorContains(t, err, "invalid user format")

	_, err = utils.ParseUser("user1:password123:ABC:EXTRA") // Too many parts
	assert.ErrorContains(t, err, "invalid user format")

	_, err = utils.ParseUser("user1::ABC")
	assert.ErrorContains(t, err, "invalid user format")

	_, err = utils.ParseUser(":password123:ABC")
	assert.ErrorContains(t, err, "invalid user format")

	_, err = utils.ParseUser("   :   :   ")
	assert.ErrorContains(t, err, "invalid user format")
}
