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
	result, err := utils.GetCookieDomain(domain)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)

	// Domain with multiple subdomains
	domain = "http://b.c.tinyauth.app"
	expected = "c.tinyauth.app"
	result, err = utils.GetCookieDomain(domain)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)

	// Invalid domain (only TLD)
	domain = "com"
	_, err = utils.GetCookieDomain(domain)
	assert.ErrorContains(t, err, "invalid app url, must be at least second level domain")

	// IP address
	domain = "http://10.10.10.10"
	_, err = utils.GetCookieDomain(domain)
	assert.ErrorContains(t, err, "ip addresses not allowed")

	// Invalid URL
	domain = "http://[::1]:namedport"
	_, err = utils.GetCookieDomain(domain)
	assert.ErrorContains(t, err, "parse \"http://[::1]:namedport\": invalid port \":namedport\" after host")

	// URL with scheme and path
	domain = "https://sub.tinyauth.app/path"
	expected = "tinyauth.app"
	result, err = utils.GetCookieDomain(domain)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)

	// URL with port
	domain = "http://sub.tinyauth.app:8080"
	expected = "tinyauth.app"
	result, err = utils.GetCookieDomain(domain)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)

	// Domain managed by ICANN
	domain = "http://example.co.uk"
	_, err = utils.GetCookieDomain(domain)
	assert.Error(t, err, "domain in public suffix list, cannot set cookies")
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

func TestIsRedirectSafe(t *testing.T) {
	// Setup
	domain := "example.com"

	// Case with no subdomain
	redirectURL := "http://example.com/welcome"
	result := utils.IsRedirectSafe(redirectURL, domain)
	assert.True(t, result)

	// Case with different domain
	redirectURL = "http://malicious.com/phishing"
	result = utils.IsRedirectSafe(redirectURL, domain)
	assert.False(t, result)

	// Case with subdomain
	redirectURL = "http://sub.example.com/page"
	result = utils.IsRedirectSafe(redirectURL, domain)
	assert.True(t, result)

	// Case with sub-subdomain
	redirectURL = "http://a.b.example.com/home"
	result = utils.IsRedirectSafe(redirectURL, domain)
	assert.True(t, result)

	// Case with empty redirect URL
	redirectURL = ""
	result = utils.IsRedirectSafe(redirectURL, domain)
	assert.False(t, result)

	// Case with invalid URL
	redirectURL = "http://[::1]:namedport"
	result = utils.IsRedirectSafe(redirectURL, domain)
	assert.False(t, result)

	// Case with URL having port
	redirectURL = "http://sub.example.com:8080/page"
	result = utils.IsRedirectSafe(redirectURL, domain)
	assert.True(t, result)

	// Case with URL having different subdomain
	redirectURL = "http://another.example.com/page"
	result = utils.IsRedirectSafe(redirectURL, domain)
	assert.True(t, result)

	// Case with URL having different TLD
	redirectURL = "http://example.org/page"
	result = utils.IsRedirectSafe(redirectURL, domain)
	assert.False(t, result)

	// Case with malicious domain
	redirectURL = "https://malicious-example.com/yoyo"
	result = utils.IsRedirectSafe(redirectURL, domain)
	assert.False(t, result)
}

func TestGetStandaloneCookieDomain(t *testing.T) {
	// Normal case
	domain := "http://tinyauth.app"
	expected := "tinyauth.app"
	result, err := utils.GetStandaloneCookieDomain(domain)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)

	// URL with subdomain (full hostname is returned, no subdomain stripping)
	domain = "http://sub.tinyauth.app"
	expected = "sub.tinyauth.app"
	result, err = utils.GetStandaloneCookieDomain(domain)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)

	// URL with port (port should be stripped)
	domain = "http://tinyauth.app:8080"
	expected = "tinyauth.app"
	result, err = utils.GetStandaloneCookieDomain(domain)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)

	// URL with path
	domain = "https://tinyauth.app/some/path"
	expected = "tinyauth.app"
	result, err = utils.GetStandaloneCookieDomain(domain)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)

	// IP address
	domain = "http://10.10.10.10"
	_, err = utils.GetStandaloneCookieDomain(domain)
	assert.ErrorContains(t, err, "ip addresses not allowed")

	// Invalid domain (only TLD)
	domain = "com"
	_, err = utils.GetStandaloneCookieDomain(domain)
	assert.ErrorContains(t, err, "invalid app url")

	// Invalid URL
	domain = "http://[::1]:namedport"
	_, err = utils.GetStandaloneCookieDomain(domain)
	assert.ErrorContains(t, err, "parse \"http://[::1]:namedport\": invalid port \":namedport\" after host")
}
