package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHealthcheckTarget(t *testing.T) {
	tests := []struct {
		addr, port, socket string
		url, socketPath    string
	}{
		{"", "", "", "http://127.0.0.1:3000", ""},
		{"0.0.0.0", "3003", "", "http://127.0.0.1:3003", ""},
		{"::", "3000", "", "http://[::1]:3000", ""},
		{"[::]", "3000", "", "http://[::1]:3000", ""},
		{"::1", "3000", "", "http://[::1]:3000", ""},
		{"fe80::1%eth0", "3000", "", "http://[fe80::1%25eth0]:3000", ""},
		{"[fe80::1%eth0]", "3000", "", "http://[fe80::1%25eth0]:3000", ""},
		{"192.0.2.10", "", "", "http://192.0.2.10:3000", ""},
		{"tinyauth", "8080", "", "http://tinyauth:8080", ""},
		{"0.0.0.0", "3000", "/run/tinyauth.sock", "http://tinyauth", "/run/tinyauth.sock"},
	}

	for _, tt := range tests {
		url, socketPath := healthcheckTarget(tt.addr, tt.port, tt.socket)
		assert.Equal(t, tt.url, url, "addr=%q port=%q socket=%q", tt.addr, tt.port, tt.socket)
		assert.Equal(t, tt.socketPath, socketPath, "addr=%q port=%q socket=%q", tt.addr, tt.port, tt.socket)
	}
}
