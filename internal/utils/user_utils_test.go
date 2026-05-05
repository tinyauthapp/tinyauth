package utils_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils"
)

func TestGetUsers(t *testing.T) {
	tmpDir := t.TempDir()

	hash := "$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G"

	// Setup
	file, err := os.Create(tmpDir + "/tinyauth_users_test.txt")
	require.NoError(t, err)

	_, err = file.WriteString("      user1:" + hash + "        \n         user2:" + hash + "                    ") // Spacing is on purpose
	require.NoError(t, err)

	err = file.Close()
	require.NoError(t, err)
	defer os.Remove(tmpDir + "/tinyauth_users_test.txt")

	noAttrs := map[string]model.UserAttributes{}

	// Test file only
	users, err := utils.GetUsers([]string{}, tmpDir+"/tinyauth_users_test.txt", noAttrs)

	assert.NoError(t, err)
	assert.NotNil(t, users)
	assert.Len(t, *users, 2)

	assert.Equal(t, "user1", (*users)[0].Username)
	assert.Equal(t, hash, (*users)[0].Password)
	assert.Equal(t, "user2", (*users)[1].Username)
	assert.Equal(t, hash, (*users)[1].Password)

	// Test inline config only
	users, err = utils.GetUsers([]string{"user3:" + hash, "user4:" + hash}, "", noAttrs)

	assert.NoError(t, err)

	assert.Len(t, *users, 2)
	assert.Equal(t, "user3", (*users)[0].Username)
	assert.Equal(t, "user4", (*users)[1].Username)

	// Test both
	users, err = utils.GetUsers([]string{"user5:" + hash}, tmpDir+"/tinyauth_users_test.txt", noAttrs)

	assert.NoError(t, err)

	assert.Len(t, *users, 3)

	usernames := map[string]bool{}
	for _, u := range *users {
		usernames[u.Username] = true
	}
	assert.True(t, usernames["user1"])
	assert.True(t, usernames["user2"])
	assert.True(t, usernames["user5"])

	// Test attributes applied from userAttributes map
	attrs := map[string]model.UserAttributes{
		"user1": {Name: "User One", Email: "user1@example.com"},
	}
	users, err = utils.GetUsers([]string{}, tmpDir+"/tinyauth_users_test.txt", attrs)

	assert.NoError(t, err)
	assert.Len(t, *users, 2)

	for _, u := range *users {
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

	assert.NoError(t, err)
	assert.Nil(t, users)

	// Test non-existent file
	users, err = utils.GetUsers([]string{}, tmpDir+"/non_existent_file.txt", noAttrs)

	assert.ErrorContains(t, err, "no such file or directory")
	assert.Nil(t, users)
}

func TestParseUser(t *testing.T) {
	hash := "$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G"

	// Valid user without TOTP
	user, err := utils.ParseUser("user1:" + hash)

	assert.NoError(t, err)

	assert.Equal(t, "user1", user.Username)
	assert.Equal(t, hash, user.Password)
	assert.Equal(t, "", user.TOTPSecret)

	// Valid user with TOTP
	user, err = utils.ParseUser("user2:" + hash + ":ABCDEF")

	assert.NoError(t, err)

	assert.Equal(t, "user2", user.Username)
	assert.Equal(t, hash, user.Password)
	assert.Equal(t, "ABCDEF", user.TOTPSecret)

	// Valid user with $$ in password
	user, err = utils.ParseUser("user3:pa$$word123")

	assert.NoError(t, err)

	assert.Equal(t, "user3", user.Username)
	assert.Equal(t, "pa$word123", user.Password)
	assert.Equal(t, "", user.TOTPSecret)

	// User with spaces
	user, err = utils.ParseUser("   user4   :   password123   :   TOTPSECRET   ")

	assert.NoError(t, err)

	assert.Equal(t, "user4", user.Username)
	assert.Equal(t, "password123", user.Password)
	assert.Equal(t, "TOTPSECRET", user.TOTPSecret)

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
