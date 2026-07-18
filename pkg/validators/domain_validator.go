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
	"strings"

	"golang.org/x/net/idna"
)

// Errors
var (
	ErrSchemeMismatch   = fmt.Errorf("scheme mismatch")
	ErrPortMismatch     = fmt.Errorf("port mismatch")
	ErrHostnameMismatch = fmt.Errorf("hostname mismatch")
)

// DomainValidatorOptions is a set of options for DomainValidator.
type DomainValidatorOptions struct {
	// Ensure domains have the same scheme.
	WithScheme bool
	// Ensure domains have the same port.
	WithPort bool
	// Specify a list of allowed schemes if WithScheme is set to true.
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

func (v *DomainValidator) checkScheme(rawURL string) error {
	if !v.opts.WithScheme {
		return nil
	}

	if len(v.opts.AllowedSchemes) == 0 {
		return fmt.Errorf("allowed schemes must be specified")
	}

	for _, scheme := range v.opts.AllowedSchemes {
		if strings.HasPrefix(strings.ToLower(rawURL), strings.ToLower(scheme)+"://") {
			return nil
		}
	}

	return fmt.Errorf("invalid scheme")

}

func (v *DomainValidator) getURL(i string) (*url.URL, error) {
	if i == "" {
		return nil, fmt.Errorf("url cannot be empty")
	}

	if v.opts.WithScheme {
		err := v.checkScheme(i)

		if err != nil {
			return nil, fmt.Errorf("invalid scheme: %w", err)
		}

		u, err := url.Parse(i)

		if err != nil {
			return nil, fmt.Errorf("failed to parse input url: %w", err)
		}

		if u.Host == "" || u.Scheme == "" {
			return nil, fmt.Errorf("missing host or scheme in url: %s", i)
		}

		return u, nil
	}

	rawURL := i

	if !strings.Contains(i, "://") {
		// From godoc: [scheme:][//[userinfo@]host][/]path[?query][#fragment]
		// So, we can omit the colon and tell the Go URL lib that we want
		// to parse the URL without the scheme. If we don't do this,
		// the URL lib will parse our entire domain as the path.
		rawURL = "//" + i
	}

	u, err := url.Parse(rawURL)

	if err != nil {
		return nil, fmt.Errorf("failed to parse host: %w", err)
	}

	if u.Host == "" {
		return nil, fmt.Errorf("missing host in url: %s", i)
	}

	return u, nil
}

func (v *DomainValidator) getHostname(hostname string) (string, error) {
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
			return ErrSchemeMismatch
		}
	}

	if v.opts.WithPort {
		if eu.Port() != au.Port() {
			return ErrPortMismatch
		}
	}

	euf, err := v.getHostname(eu.Hostname())

	if err != nil {
		return err
	}

	auf, err := v.getHostname(au.Hostname())

	if err != nil {
		return err
	}

	if euf != auf {
		return ErrHostnameMismatch
	}

	return nil
}

// SafeHostname uses the internal validation for domains that the validator uses
// to parse a hostname. It ensures the input URL is a valid URL, that a host
// is present and that the hostname is lowercased and without a trailing dot.
func (v *DomainValidator) SafeHostname(input string) (string, error) {
	u, err := v.getURL(input)

	if err != nil {
		return "", err
	}

	return v.getHostname(u.Hostname())
}
