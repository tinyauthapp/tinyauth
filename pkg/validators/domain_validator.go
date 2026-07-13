// Package validators provides validators for various types of data.
//
// Domain validator is a simple utility that ensures two domains are exact
// matches while ensuring that techniques used to bypass such checks do
// not impact the validation.

package validators

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/net/idna"
)

// DomainValidatorOptions is a set of options for DomainValidator.
type DomainValidatorOptions struct {
	// Ensure domains have the same scheme.
	WithScheme bool
	// Ensure domains have the same port.
	WithPort bool
	// Specify a list of allowed schemes IF WithScheme is set to true.
	// Leave empty to allow any scheme.
	AllowedSchemes []string
}

// DomainValidator is a simple utility that ensures two domains are exact
// matches while ensuring that techniques used to bypass such checks do
// not impact the validation.
type DomainValidator struct {
	opts DomainValidatorOptions
}

// NewDomainValidator creates a new DomainValidator.
func NewDomainValidator(opts DomainValidatorOptions) *DomainValidator {
	return &DomainValidator{
		opts: opts,
	}
}

func (v *DomainValidator) getURL(i string) (*url.URL, error) {
	u, err := url.Parse(i)

	if !v.opts.WithScheme && (err != nil || u.Host == "") {
		u, err = url.Parse("tinyauth://" + i)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse input url: %w", err)
	}

	if u.Host == "" {
		return nil, fmt.Errorf("input url is invalid")
	}

	if v.opts.WithPort && !v.opts.WithScheme && u.Port() == "" {
		return nil, fmt.Errorf("port validation is enabled but port is missing in input url and schemes are not enabled")
	}

	if v.opts.WithScheme {
		// Empty scheme means that we parsed the url with the tinyauth:// placeholder
		if u.Scheme == "tinyauth" {
			return nil, fmt.Errorf("input url is missing scheme")
		}
		if len(v.opts.AllowedSchemes) > 0 && !slices.Contains(v.opts.AllowedSchemes, u.Scheme) {
			return nil, fmt.Errorf("scheme %s not allowed", u.Scheme)
		}
	}

	return u, nil
}

func (v *DomainValidator) getEffectivePort(u *url.URL) string {
	if u.Port() != "" {
		return u.Port()
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func (v *DomainValidator) formatHostname(hostname string) (string, error) {
	hostname = strings.ToLower(hostname)
	hostname = strings.TrimSuffix(hostname, ".")
	if net.ParseIP(hostname) != nil {
		return "", fmt.Errorf("ip addresses are not supported")
	}
	hostname, err := idna.Lookup.ToASCII(hostname)
	if err != nil {
		return "", fmt.Errorf("failed to convert hostname to ascii: %w", err)
	}
	return hostname, nil
}

// Validate ensures that two domains are exact matches with the
// options defined in the DomainValidatorOptions. It ensures that the
// inputs are proper URLs and contain a host. It lowercases the hostnames
// and removes the trailing dot. Finally, it checks that the hostnames are
// equal unless WithScheme or WithPort is set to true where it also
// validates the scheme and port respectively.
func (v *DomainValidator) Validate(expected, actual string) error {
	eu, err := v.getURL(expected)

	if err != nil {
		return err
	}

	au, err := v.getURL(actual)

	if err != nil {
		return err
	}

	if v.opts.WithScheme {
		if eu.Scheme != au.Scheme {
			return fmt.Errorf("expected scheme %s, got %s", eu.Scheme, au.Scheme)
		}
	}

	if v.opts.WithPort {
		if v.getEffectivePort(eu) != v.getEffectivePort(au) {
			return fmt.Errorf("expected port %s, got %s", v.getEffectivePort(eu), v.getEffectivePort(au))
		}
	}

	euf, err := v.formatHostname(eu.Hostname())

	if err != nil {
		return err
	}

	auf, err := v.formatHostname(au.Hostname())

	if err != nil {
		return err
	}

	if euf != auf {
		return fmt.Errorf("expected hostname %s, got %s", euf, auf)
	}

	return nil
}

// SafeHostname uses the internal validation for domains that Validator uses
// to parse a hostname. It ensures the input URL is a valid URL, that a host
// is present and that the hostname is lowercased and without a trailing dot.
func (v *DomainValidator) SafeHostname(input string) (string, error) {
	u, err := v.getURL(input)

	if err != nil {
		return "", err
	}

	return v.formatHostname(u.Hostname())
}
