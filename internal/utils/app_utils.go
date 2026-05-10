package utils

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/weppos/publicsuffix-go/publicsuffix"
)

// Get cookie domain parses a hostname and returns the upper domain (e.g. sub1.sub2.domain.com -> sub2.domain.com)
func GetCookieDomain(u string) (string, error) {
	parsed, err := url.Parse(u)
	if err != nil {
		return "", err
	}

	host := parsed.Hostname()

	if netIP := net.ParseIP(host); netIP != nil {
		return "", errors.New("ip addresses not allowed")
	}

	parts := strings.Split(host, ".")

	if len(parts) == 2 {
		return host, nil
	}

	if len(parts) < 3 {
		return "", errors.New("invalid app url, must be at least second level domain")
	}

	domain := strings.Join(parts[1:], ".")

	_, err = publicsuffix.DomainFromListWithOptions(publicsuffix.DefaultList, domain, nil)

	if err != nil {
		return "", errors.New("domain in public suffix list, cannot set cookies")
	}

	return domain, nil
}

func GetStandaloneCookieDomain(u string) (string, error) {
	parsed, err := url.Parse(u)
	if err != nil {
		return "", err
	}

	host := parsed.Hostname()

	if netIP := net.ParseIP(host); netIP != nil {
		return "", errors.New("ip addresses not allowed")
	}

	parts := strings.Split(host, ".")

	if len(parts) < 2 {
		return "", errors.New("invalid app url")
	}

	return host, nil
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

func IsRedirectSafe(redirectURL string, domain string) bool {
	if redirectURL == "" {
		return false
	}

	parsed, err := url.Parse(redirectURL)

	if err != nil {
		return false
	}

	hostname := parsed.Hostname()

	if strings.HasSuffix(hostname, fmt.Sprintf(".%s", domain)) {
		return true
	}

	return hostname == domain
}
