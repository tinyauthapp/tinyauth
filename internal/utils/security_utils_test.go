package utils_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/utils"
)

func TestGetSecret(t *testing.T) {
	// Setup
	file, err := os.Create("/tmp/tinyauth_test_secret")
	require.NoError(t, err)

	_, err = file.WriteString("       secret       \n")
	require.NoError(t, err)

	err = file.Close()
	require.NoError(t, err)
	defer os.Remove("/tmp/tinyauth_test_secret")

	// Get from config
	assert.Equal(t, "mysecret", utils.GetSecret("mysecret", ""))

	// Get from file
	assert.Equal(t, "secret", utils.GetSecret("", "/tmp/tinyauth_test_secret"))

	// Get from both (config should take precedence)
	assert.Equal(t, "mysecret", utils.GetSecret("mysecret", "/tmp/tinyauth_test_secret"))

	// Get from none
	assert.Equal(t, "", utils.GetSecret("", ""))

	// Get from non-existing file
	assert.Equal(t, "", utils.GetSecret("", "/tmp/non_existing_file"))
}

func TestParseSecretFile(t *testing.T) {
	// Normal case
	content := "   mysecret   \n"
	assert.Equal(t, "mysecret", utils.ParseSecretFile(content))

	// Multiple lines (should take the first non-empty line)
	content = "\n\n   firstsecret   \nsecondsecret\n"
	assert.Equal(t, "firstsecret", utils.ParseSecretFile(content))

	// All empty lines
	content = "\n   \n  \n"
	assert.Equal(t, "", utils.ParseSecretFile(content))

	// Empty content
	content = ""
	assert.Equal(t, "", utils.ParseSecretFile(content))
}

func TestEncodeBasicAuth(t *testing.T) {
	// Normal case
	username := "user"
	password := "pass"
	expected := "dXNlcjpwYXNz" // base64 of "user:pass"
	assert.Equal(t, expected, utils.EncodeBasicAuth(username, password))

	// Empty username
	username = ""
	password = "pass"
	expected = "OnBhc3M=" // base64 of ":pass"
	assert.Equal(t, expected, utils.EncodeBasicAuth(username, password))

	// Empty password
	username = "user"
	password = ""
	expected = "dXNlcjo=" // base64 of "user:"
	assert.Equal(t, expected, utils.EncodeBasicAuth(username, password))
}

func TestFilterIP(t *testing.T) {
	// Exact match IPv4
	ok, err := utils.FilterIP("10.10.0.1", "10.10.0.1")
	assert.NoError(t, err)
	assert.Equal(t, true, ok)

	// Non-match IPv4
	ok, err = utils.FilterIP("10.10.0.1", "10.10.0.2")
	assert.NoError(t, err)
	assert.Equal(t, false, ok)

	// CIDR match IPv4
	ok, err = utils.FilterIP("10.10.0.0/24", "10.10.0.2")
	assert.NoError(t, err)
	assert.Equal(t, true, ok)

	// CIDR match IPv4 with '-' instead of '/'
	ok, err = utils.FilterIP("10.10.10.0-24", "10.10.10.5")
	assert.NoError(t, err)
	assert.Equal(t, true, ok)

	// CIDR non-match IPv4
	ok, err = utils.FilterIP("10.10.0.0/24", "10.5.0.1")
	assert.NoError(t, err)
	assert.Equal(t, false, ok)

	// Invalid CIDR
	ok, err = utils.FilterIP("10.10.0.0/222", "10.0.0.1")
	assert.ErrorContains(t, err, "invalid CIDR address")
	assert.Equal(t, false, ok)

	// Invalid IP in filter
	ok, err = utils.FilterIP("invalid_ip", "10.5.5.5")
	assert.ErrorContains(t, err, "invalid IP address in filter")
	assert.Equal(t, false, ok)

	// Invalid IP to check
	ok, err = utils.FilterIP("10.10.10.10", "invalid_ip")
	assert.ErrorContains(t, err, "invalid IP address")
	assert.Equal(t, false, ok)
}

func TestCheckFilter(t *testing.T) {
	// Empty filter
	assert.Equal(t, true, utils.CheckFilter("", "anystring"))

	// Exact match
	assert.Equal(t, true, utils.CheckFilter("hello", "hello"))

	// Regex match
	assert.Equal(t, true, utils.CheckFilter("/^h.*o$/", "hello"))

	// Invalid regex
	assert.Equal(t, false, utils.CheckFilter("/[unclosed", "test"))

	// Comma-separated values
	assert.Equal(t, true, utils.CheckFilter("apple, banana, cherry", "banana"))

	// No match
	assert.Equal(t, false, utils.CheckFilter("apple, banana, cherry", "grape"))
}

func TestGenerateUUID(t *testing.T) {
	// Consistent output for same input
	id1 := utils.GenerateUUID("teststring")
	id2 := utils.GenerateUUID("teststring")
	assert.Equal(t, id1, id2)

	// Different output for different input
	id3 := utils.GenerateUUID("differentstring")
	assert.NotEqual(t, id2, id3)
}
