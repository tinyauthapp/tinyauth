package utils

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadFile(t *testing.T) {
	// Setup
	file, err := os.Create("/tmp/tinyauth_test_file")
	assert.NoError(t, err)

	_, err = file.WriteString("file content\n")
	assert.NoError(t, err)

	err = file.Close()
	assert.NoError(t, err)
	defer os.Remove("/tmp/tinyauth_test_file")

	// Normal case
	content, err := ReadFile("/tmp/tinyauth_test_file")
	assert.NoError(t, err)
	assert.Equal(t, "file content\n", content)

	// Non-existing file
	content, err = ReadFile("/tmp/non_existing_file")
	assert.ErrorContains(t, err, "no such file or directory")
	assert.Equal(t, "", content)
}
