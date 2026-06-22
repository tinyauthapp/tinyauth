package utils_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tinyauthapp/tinyauth/internal/utils"
)

func TestGetRootDomain(t *testing.T) {
	// Normal case
	domain := "http://sub.tinyauth.app"
	expected := "tinyauth.app"
	result, err := utils.GetCookieDomain(domain, true)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)

	// Domain with multiple subdomains
	domain = "http://b.c.tinyauth.app"
	expected = "c.tinyauth.app"
	result, err = utils.GetCookieDomain(domain, true)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)

	// Invalid domain (only TLD)
	domain = "com"
	_, err = utils.GetCookieDomain(domain, true)
	assert.EqualError(t, err, "invalid app url, must be in format subdomain.domain.tld or domain.tld")

	// IP address
	domain = "http://10.10.10.10"
	_, err = utils.GetCookieDomain(domain, true)
	assert.ErrorContains(t, err, "ip addresses not allowed")

	// Invalid URL
	domain = "http://[::1]:namedport"
	_, err = utils.GetCookieDomain(domain, true)
	assert.ErrorContains(t, err, "parse \"http://[::1]:namedport\": invalid port \":namedport\" after host")

	// URL with scheme and path
	domain = "https://sub.tinyauth.app/path"
	expected = "tinyauth.app"
	result, err = utils.GetCookieDomain(domain, true)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)

	// URL with port
	domain = "http://sub.tinyauth.app:8080"
	expected = "tinyauth.app"
	result, err = utils.GetCookieDomain(domain, true)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)

	// Domain managed by ICANN
	domain = "http://example.co.uk"
	_, err = utils.GetCookieDomain(domain, true)
	assert.ErrorContains(t, err, "domain in public suffix list, cannot set cookies")

	// Domain without subdomain
	domain = "http://tinyauth.app"
	expected = "tinyauth.app"
	result, err = utils.GetCookieDomain(domain, true)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)

	// Case insensitivity
	domain = "http://Sub.Tinyauth.App"
	expected = "tinyauth.app"
	result, err = utils.GetCookieDomain(domain, true)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)

	// Subdomains disabled
	domain = "http://sub.tinyauth.app"
	expected = "sub.tinyauth.app"
	result, err = utils.GetCookieDomain(domain, false)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}

func TestParseFileToLine(t *testing.T) {
	// Normal case
	content := "user1\nuser2\nuser3"
	expected := "user1,user2,user3"
	result := utils.ParseFileToLine(content)
	assert.Equal(t, expected, result)

	// Case with empty lines and spaces
	content = " user1 \n\n user2 \n user3 \n"
	expected = "user1,user2,user3"
	result = utils.ParseFileToLine(content)
	assert.Equal(t, expected, result)

	// Case with only empty lines
	content = "\n\n\n"
	expected = ""
	result = utils.ParseFileToLine(content)
	assert.Equal(t, expected, result)

	// Case with single user
	content = "singleuser"
	expected = "singleuser"
	result = utils.ParseFileToLine(content)
	assert.Equal(t, expected, result)

	// Case with trailing newline
	content = "user1\nuser2\n"
	expected = "user1,user2"
	result = utils.ParseFileToLine(content)
	assert.Equal(t, expected, result)
}

func TestFilter(t *testing.T) {
	// Normal case
	slice := []int{1, 2, 3, 4, 5}
	testFunc := func(n int) bool { return n%2 == 0 }
	expected := []int{2, 4}
	result := utils.Filter(slice, testFunc)
	assert.Equal(t, expected, result)

	// Case with no matches
	slice = []int{1, 3, 5}
	testFunc = func(n int) bool { return n%2 == 0 }
	expected = []int{}
	result = utils.Filter(slice, testFunc)
	assert.Equal(t, expected, result)

	// Case with all matches
	slice = []int{2, 4, 6}
	testFunc = func(n int) bool { return n%2 == 0 }
	expected = []int{2, 4, 6}
	result = utils.Filter(slice, testFunc)
	assert.Equal(t, expected, result)

	// Case with empty slice
	slice = []int{}
	testFunc = func(n int) bool { return n%2 == 0 }
	expected = []int{}
	result = utils.Filter(slice, testFunc)
	assert.Equal(t, expected, result)

	// Case with different type (string)
	sliceStr := []string{"apple", "banana", "cherry"}
	testFuncStr := func(s string) bool { return len(s) > 5 }
	expectedStr := []string{"banana", "cherry"}
	resultStr := utils.Filter(sliceStr, testFuncStr)
	assert.Equal(t, expectedStr, resultStr)
}
