package utils_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tinyauthapp/tinyauth/internal/utils"
)

func TestCapitalize(t *testing.T) {
	// Test empty string
	assert.Equal(t, "", utils.Capitalize(""))

	// Test single character
	assert.Equal(t, "A", utils.Capitalize("a"))

	// Test multiple characters
	assert.Equal(t, "Hello", utils.Capitalize("hello"))

	// Test already capitalized
	assert.Equal(t, "World", utils.Capitalize("World"))

	// Test non-alphabetic first character
	assert.Equal(t, "1number", utils.Capitalize("1number"))

	// Test Unicode characters
	assert.Equal(t, "Γειά", utils.Capitalize("γειά"))
	assert.Equal(t, "Привет", utils.Capitalize("привет"))

}

func TestCoalesceToString(t *testing.T) {
	// Test with []any containing strings
	assert.Equal(t, "a,b,c", utils.CoalesceToString([]any{"a", "b", "c"}))

	// Test with []any containing mixed types
	assert.Equal(t, "a,c", utils.CoalesceToString([]any{"a", 1, "c", true}))

	// Test with []any containing no strings
	assert.Equal(t, "", utils.CoalesceToString([]any{1, 2, 3}))

	// Test with string input
	assert.Equal(t, "hello", utils.CoalesceToString("hello"))

	// Test with non-string, non-[]any input
	assert.Equal(t, "", utils.CoalesceToString(123))

	// Test with nil input
	assert.Equal(t, "", utils.CoalesceToString(nil))
}

func TestCompileUserEmail(t *testing.T) {
	// Test with valid email
	assert.Equal(t, "user@example.com", utils.CompileUserEmail("user@example.com", "example.com"))

	// Test with invalid email
	assert.Equal(t, "user@example.com", utils.CompileUserEmail("user", "example.com"))
}

func TestParseNonEmptyLines(t *testing.T) {
	lines := utils.ParseNonEmptyLines(" first@example.com \n\n second@example.com \n   \n")

	assert.Equal(t, []string{"first@example.com", "second@example.com"}, lines)
}

func TestGetStringList(t *testing.T) {
	file, err := os.Create("/tmp/tinyauth_list_test_file")
	assert.NoError(t, err)

	_, err = file.WriteString(" third@example.com \n\n fourth@example.com \n")
	assert.NoError(t, err)

	err = file.Close()
	assert.NoError(t, err)
	defer os.Remove("/tmp/tinyauth_list_test_file")

	values, err := utils.GetStringList([]string{" first@example.com ", "", "second@example.com"}, "/tmp/tinyauth_list_test_file")
	assert.NoError(t, err)
	assert.Equal(t, []string{"first@example.com", "second@example.com", "third@example.com", "fourth@example.com"}, values)

	values, err = utils.GetStringList(nil, "")
	assert.NoError(t, err)
	assert.Equal(t, []string{}, values)

	values, err = utils.GetStringList(nil, "/tmp/non_existing_list_file")
	assert.ErrorContains(t, err, "no such file or directory")
	assert.Equal(t, []string{}, values)
}
