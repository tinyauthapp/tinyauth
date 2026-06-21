package utils

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/weppos/publicsuffix-go/publicsuffix"
)

// Get cookie domain parses a hostname and returns the upper domain (e.g. sub1.sub2.domain.com -> sub2.domain.com)
func GetCookieDomain(appUrl string, subdomainsEnabled bool) (string, error) {
	u, err := url.Parse(appUrl)

	if err != nil {
		return "", fmt.Errorf("invalid app url: %w", err)
	}

	hostname := strings.ToLower(u.Hostname())

	if netIP := net.ParseIP(hostname); netIP != nil {
		return "", fmt.Errorf("ip addresses not allowed")
	}

	parts := strings.Split(hostname, ".")

	if len(parts) < 2 {
		return "", fmt.Errorf("invalid app url, must be in format subdomain.domain.tld or domain.tld")
	}

	if !subdomainsEnabled || len(parts) == 2 {
		_, err = publicsuffix.DomainFromListWithOptions(publicsuffix.DefaultList, hostname, nil)

		if err != nil {
			return "", fmt.Errorf("domain in public suffix list, cannot set cookies: %w", err)
		}

		return strings.ToLower(u.Host), nil
	}

	domain := strings.Join(parts[1:], ".")

	_, err = publicsuffix.DomainFromListWithOptions(publicsuffix.DefaultList, domain, nil)

	if err != nil {
		return "", fmt.Errorf("domain in public suffix list, cannot set cookies: %w", err)
	}

	// now that we validated the domain, return with the port
	parts = strings.Split(strings.ToLower(u.Host), ".")
	host := strings.Join(parts[1:], ".")

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
