package validators

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDomainValidator_SafeHostname(t *testing.T) {
	type testCase struct {
		description string
		options     DomainValidatorOptions
		input       string
		expected    string
		errorFunc   func(t *testing.T, e error)
	}

	tests := []testCase{
		{
			description: "Empty url fails",
			errorFunc: func(t *testing.T, e error) {
				assert.ErrorContains(t, e, "input url is invalid")
			},
		},
		{
			description: "Invalid url fails",
			input:       "foo:foo",
			errorFunc: func(t *testing.T, e error) {
				assert.ErrorContains(t, e, "failed to parse input url")
			},
		},
		{
			description: "Domain without scheme should parse if scheme is disabled",
			input:       "example.com",
			expected:    "example.com",
		},
		{
			description: "Domain without scheme should not parse if scheme is enabled",
			options:     DomainValidatorOptions{WithScheme: true},
			input:       "example.com",
			errorFunc: func(t *testing.T, e error) {
				assert.ErrorContains(t, e, "input url is invalid")
			},
		},
		{
			description: "Domain with scheme and disallowed scheme should fail",
			options:     DomainValidatorOptions{WithScheme: true, AllowedSchemes: []string{"https"}},
			input:       "foo://example.com",
			errorFunc: func(t *testing.T, e error) {
				assert.ErrorContains(t, e, "foo not allowed")
			},
		},
		{
			description: "Domain with scheme and allowed scheme should pass",
			options:     DomainValidatorOptions{WithScheme: true, AllowedSchemes: []string{"https"}},
			input:       "https://example.com",
			expected:    "example.com",
		},
		{
			description: "Domain should get lowercased",
			input:       "EXAMPLE.COM",
			expected:    "example.com",
		},
		{
			description: "DNS dot should be removed",
			input:       "example.com.",
			expected:    "example.com",
		},
		{
			description: "IPv4 address should fail",
			input:       "127.0.0.1",
			errorFunc: func(t *testing.T, e error) {
				assert.ErrorContains(t, e, "ip addresses are not supported")
			},
		},
		{
			description: "IPv6 address should fail",
			input:       "[::1]",
			errorFunc: func(t *testing.T, e error) {
				assert.ErrorContains(t, e, "ip addresses are not supported")
			},
		},
		{
			description: "Domains with unicode characters should be allowed",
			input:       "bücher.example.com",
			expected:    "xn--bcher-kva.example.com",
		},
		{
			description: "Invalid IDNA domain should fail",
			input:       "ab--cd.example.com",
			errorFunc: func(t *testing.T, e error) {
				assert.ErrorContains(t, e, "invalid label")
			},
		},
		{
			// Placeholder should not be used by users and is reserved for the validator.
			// Using it is like not using any scheme for the validator, and thus it will fail
			// with schemes enabled.
			description: "Placeholder scheme supplied directly should fail",
			options:     DomainValidatorOptions{WithScheme: true, AllowedSchemes: []string{"https"}},
			input:       "tinyauth://example.com",
			errorFunc: func(t *testing.T, e error) {
				assert.ErrorContains(t, e, "input url is missing scheme")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			v := NewDomainValidator(test.options)
			res, err := v.SafeHostname(test.input)
			if test.errorFunc != nil {
				test.errorFunc(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expected, res)
		})
	}
}

func TestDomainValidator_Validate(t *testing.T) {
	type testCase struct {
		description string
		options     DomainValidatorOptions
		expected    string
		actual      string
		errorFunc   func(t *testing.T, e error)
	}

	tests := []testCase{
		{
			description: "Invalid expected domain fails checks",
			expected:    "foo:foo",
			actual:      "bar.com",
			errorFunc: func(t *testing.T, e error) {
				assert.ErrorContains(t, e, "failed to parse input url")
			},
		},
		{
			description: "Invalid check domain fails checks",
			expected:    "example.com",
			actual:      "foo:foo",
			errorFunc: func(t *testing.T, e error) {
				assert.ErrorContains(t, e, "failed to parse input url")
			},
		},
		{
			description: "Valid domains with non-matching schemes should fail",
			options:     DomainValidatorOptions{WithScheme: true, AllowedSchemes: []string{"https", "http"}},
			expected:    "https://example.com",
			actual:      "http://example.com",
			errorFunc: func(t *testing.T, e error) {
				assert.ErrorContains(t, e, "expected scheme https, got http")
			},
		},
		{
			description: "Valid domains with matching schemes should pass",
			options:     DomainValidatorOptions{WithScheme: true, AllowedSchemes: []string{"https", "http"}},
			expected:    "https://example.com",
			actual:      "https://example.com",
		},
		{
			description: "Port validation without ports and schemes disabled should fail",
			options:     DomainValidatorOptions{WithPort: true},
			expected:    "example.com",
			actual:      "example.com",
			errorFunc: func(t *testing.T, e error) {
				assert.ErrorContains(t, e, "port validation is enabled but port is missing in input url and schemes are not enabled")
			},
		},
		{
			description: "Port validation with no port and http should pass",
			options:     DomainValidatorOptions{WithPort: true, WithScheme: true, AllowedSchemes: []string{"http"}},
			expected:    "http://example.com",
			actual:      "http://example.com",
		},
		{
			description: "Port validation with no port and https should pass",
			options:     DomainValidatorOptions{WithPort: true, WithScheme: true, AllowedSchemes: []string{"https"}},
			expected:    "https://example.com",
			actual:      "https://example.com",
		},
		{
			description: "Port validation with port and no scheme should pass with same port",
			options:     DomainValidatorOptions{WithPort: true},
			expected:    "example.com:8080",
			actual:      "example.com:8080",
		},
		{
			description: "Port validation with port and no scheme should fail with different port",
			options:     DomainValidatorOptions{WithPort: true},
			expected:    "example.com:8080",
			actual:      "example.com:8081",
			errorFunc: func(t *testing.T, e error) {
				assert.ErrorContains(t, e, "expected port 8080, got 8081")
			},
		},
		{
			description: "Failure to format expected domain should fail",
			expected:    "ab--cd.example.com",
			actual:      "example.com",
			errorFunc: func(t *testing.T, e error) {
				assert.ErrorContains(t, e, "idna: invalid label")
			},
		},
		{
			description: "Failure to format check domain should fail",
			expected:    "example.com",
			actual:      "ab--cd.example.com",
			errorFunc: func(t *testing.T, e error) {
				assert.ErrorContains(t, e, "idna: invalid label")
			},
		},
		{
			description: "Valid domains with matching schemes and ports should pass",
			options:     DomainValidatorOptions{WithScheme: true, AllowedSchemes: []string{"https", "http"}, WithPort: true},
			expected:    "https://example.com:8080",
			actual:      "https://example.com:8080",
		},
		{
			description: "Valid domains with matching schemes should pass",
			options:     DomainValidatorOptions{WithScheme: true, AllowedSchemes: []string{"https", "http"}},
			expected:    "https://example.com",
			actual:      "https://example.com",
		},
		{
			description: "Valid domains with matching ports should pass",
			options:     DomainValidatorOptions{WithPort: true},
			expected:    "example.com:8080",
			actual:      "example.com:8080",
		},
		{
			description: "Valid domains without ports or schemes should pass",
			actual:      "example.com",
			expected:    "example.com",
		},
		{
			description: "Unicode valid domains should pass",
			expected:    "xn--bcher-kva.example.com",
			actual:      "bücher.example.com",
		},
		{
			description: "Unicode valid domains should pass (reverse)",
			expected:    "bücher.example.com",
			actual:      "xn--bcher-kva.example.com",
		},
		{
			description: "Non matching hostnames should fail",
			expected:    "example.com",
			actual:      "foo.com",
			errorFunc: func(t *testing.T, e error) {
				assert.ErrorContains(t, e, "expected hostname example.com, got foo.com")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			v := NewDomainValidator(test.options)
			err := v.Validate(test.expected, test.actual)
			if test.errorFunc != nil {
				test.errorFunc(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
