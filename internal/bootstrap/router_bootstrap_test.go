package bootstrap

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSocketMode(t *testing.T) {
	ok := map[string]os.FileMode{
		"0660": 0o660,
		"660":  0o660,
		"0600": 0o600,
		"0":    0,
		"0777": 0o777,
	}

	for in, want := range ok {
		got, err := parseSocketMode(in)
		assert.NoError(t, err, "input %q", in)
		assert.Equal(t, want, got, "input %q", in)
	}

	for _, in := range []string{"", "abc", "0800", "999", "0x1a0", "1000"} {
		_, err := parseSocketMode(in)
		assert.Error(t, err, "input %q should be rejected", in)
	}
}

// TestSocketModeAppliedToListener documents that os.Chmod on the listening socket path sets
// exactly the requested permission bits, which is what serveUnix relies on.
func TestSocketModeAppliedToListener(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Chmod cannot set Unix permission bits on Windows (socketMode is rejected there)")
	}

	path := filepath.Join(t.TempDir(), "ta.sock")

	listener, err := net.Listen("unix", path)
	require.NoError(t, err)
	defer listener.Close()

	mode, err := parseSocketMode("0660")
	require.NoError(t, err)
	require.NoError(t, os.Chmod(path, mode))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o660), info.Mode().Perm())
}
