package bootstrap

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeAppURL(t *testing.T) {
	tests := []struct {
		name     string
		rawURL   string
		expected string
	}{
		{
			name:     "trims trailing slash",
			rawURL:   "https://tinyauth.example.com/",
			expected: "https://tinyauth.example.com",
		},
		{
			name:     "ignores configured path",
			rawURL:   "https://tinyauth.example.com/auth/",
			expected: "https://tinyauth.example.com",
		},
		{
			name:     "preserves explicit port",
			rawURL:   "https://tinyauth.example.com:3000/",
			expected: "https://tinyauth.example.com:3000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appURL, err := url.Parse(tt.rawURL)
			require.NoError(t, err)

			assert.Equal(t, tt.expected, normalizeAppURL(appURL))
		})
	}
}
