package utils_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tinyauthapp/tinyauth/internal/utils"
)

func TestParseHeaders(t *testing.T) {
	// Normal case
	headers := []string{
		"X-Custom-Header=Value",
		"Another-Header=AnotherValue",
	}
	expected := map[string]string{
		"X-Custom-Header": "Value",
		"Another-Header":  "AnotherValue",
	}
	assert.Equal(t, expected, utils.ParseHeaders(headers))

	// Case insensitivity and trimming
	headers = []string{
		"  x-custom-header =  Value  ",
		"ANOTHER-HEADER=AnotherValue",
	}
	expected = map[string]string{
		"X-Custom-Header": "Value",
		"Another-Header":  "AnotherValue",
	}
	assert.Equal(t, expected, utils.ParseHeaders(headers))

	// Invalid headers (missing '=', empty key/value)
	headers = []string{
		"InvalidHeader",
		"=NoKey",
		"NoValue=",
		"   =   ",
	}
	expected = map[string]string{}
	assert.Equal(t, expected, utils.ParseHeaders(headers))

	// Headers with unsafe characters
	headers = []string{
		"X-Custom-Header=Val\x00ue",       // Null byte
		"Another-Header=Anoth\x7FerValue", // DEL character
		"Good-Header=GoodValue",
	}
	expected = map[string]string{
		"X-Custom-Header": "Value",
		"Another-Header":  "AnotherValue",
		"Good-Header":     "GoodValue",
	}
	assert.Equal(t, expected, utils.ParseHeaders(headers))

	// Header with spaces in key (should be ignored)
	headers = []string{
		"X Custom Header=Value",
		"Valid-Header=ValidValue",
	}
	expected = map[string]string{
		"Valid-Header": "ValidValue",
	}
	assert.Equal(t, expected, utils.ParseHeaders(headers))
}

func TestSanitizeHeader(t *testing.T) {
	// Normal case
	header := "X-Custom-Header"
	expected := "X-Custom-Header"
	assert.Equal(t, expected, utils.SanitizeHeader(header))

	// Header with unsafe characters
	header = "X-Cust\x00om-Hea\x7Fder" // Null byte and DEL character
	expected = "X-Custom-Header"
	assert.Equal(t, expected, utils.SanitizeHeader(header))

	// Header with only unsafe characters
	header = "\x00\x01\x02\x7F"
	expected = ""
	assert.Equal(t, expected, utils.SanitizeHeader(header))

	// Header with spaces and tabs (should be preserved)
	header = "X Custom\tHeader"
	expected = "X Custom\tHeader"
	assert.Equal(t, expected, utils.SanitizeHeader(header))
}
