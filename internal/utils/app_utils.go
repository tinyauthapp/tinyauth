package utils

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/weppos/publicsuffix-go/publicsuffix"
	"golang.org/x/net/idna"
)

var (
	ErrEmptyURL = fmt.Errorf("invalid url")
)

func SafeParseAppURL(str string) (string, error) {
	if strings.TrimSpace(str) == "" {
		return "", ErrEmptyURL
	}

	u, err := url.Parse(str)

	if err != nil {
		return "", fmt.Errorf("invalid url: %w", err)
	}

	if u.Host == "" ||
		(u.Scheme != "http" &&
			u.Scheme != "https") {
		return "", fmt.Errorf("invalid url, must be in format https(s)://host")
	}

	hostname := strings.ToLower(u.Hostname())
	hostname = strings.TrimSuffix(hostname, ".")

	if netIP := net.ParseIP(hostname); netIP != nil {
		return "", fmt.Errorf("ip addresses not allowed")
	}

	hostname, err = idna.Lookup.ToASCII(hostname)

	if err != nil {
		return "", fmt.Errorf("failed to convert hostname to ascii: %w", err)
	}

	appURL := fmt.Sprintf("%s://%s", u.Scheme, hostname)

	if u.Port() != "" {
		appURL += ":" + u.Port()
	}

	return appURL, nil
}

// GetCookieDomain parses the app URL and returns the domain value to use for cookies.
// When auth for subdomains is enabled, it strips the leftmost label
// GetCookieDomain assumes the app URL is first parsed with SafeParseAppURL
// (e.g. sub1.sub2.domain.com -> sub2.domain.com), otherwise it returns the full hostname.
func GetCookieDomain(appUrl string, subdomainsEnabled bool) (string, error) {
	u, err := url.Parse(appUrl)

	if err != nil {
		return "", fmt.Errorf("invalid app url: %w", err)
	}

	hostname := strings.ToLower(u.Hostname())

	parts := strings.Split(hostname, ".")

	if len(parts) < 2 {
		return "", fmt.Errorf("invalid app url, must be in format subdomain.domain.tld or domain.tld")
	}

	if !subdomainsEnabled || len(parts) == 2 {
		_, err = publicsuffix.DomainFromListWithOptions(publicsuffix.DefaultList, hostname, nil)

		if err != nil {
			return "", fmt.Errorf("domain in public suffix list, cannot set cookies: %w", err)
		}

		return hostname, nil
	}

	domain := strings.Join(parts[1:], ".")

	_, err = publicsuffix.DomainFromListWithOptions(publicsuffix.DefaultList, domain, nil)

	if err != nil {
		return "", fmt.Errorf("domain in public suffix list, cannot set cookies: %w", err)
	}

	return domain, nil
}

func ParseFileToLine(content string) string {
	lines := strings.Split(content, "\n")
	users := make([]string, 0)

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		users = append(users, strings.TrimSpace(line))
	}

	return strings.Join(users, ",")
}

func Filter[T any](slice []T, test func(T) bool) (res []T) {
	res = make([]T, 0)
	for _, value := range slice {
		if test(value) {
			res = append(res, value)
		}
	}
	return res
}
