package utils

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadFile(t *testing.T) {
	// Setup
	file, err := os.Create("/tmp/tinyauth_test_file")
	require.NoError(t, err)

	_, err = file.WriteString("file content\n")
	require.NoError(t, err)

	err = file.Close()
	require.NoError(t, err)
	defer os.Remove("/tmp/tinyauth_test_file")

	// Normal case
	content, err := ReadFile("/tmp/tinyauth_test_file")
	assert.NoError(t, err)
	assert.Equal(t, "file content\n", content)

	// Non-existing file
	content, err = ReadFile("/tmp/non_existing_file")
	assert.ErrorContains(t, err, "no such file or directory")
	assert.Equal(t, "", content)
}

func TestRemoveExistingSocket(t *testing.T) {
	// Short directory, unix socket paths are limited to ~108 bytes
	dir, err := os.MkdirTemp("", "ta")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	// Non-existing path
	removed, inUse, err := RemoveExistingSocket(filepath.Join(dir, "missing.sock"))
	assert.NoError(t, err)
	assert.False(t, removed)
	assert.False(t, inUse)

	// Regular file is never removed
	file := filepath.Join(dir, "regular")
	require.NoError(t, os.WriteFile(file, []byte("data"), 0600))
	removed, _, err = RemoveExistingSocket(file)
	assert.ErrorContains(t, err, "not a unix socket")
	assert.False(t, removed)
	assert.FileExists(t, file)

	// Symlink to a regular file is never removed
	fileLink := filepath.Join(dir, "regular.link")
	require.NoError(t, os.Symlink(file, fileLink))
	removed, _, err = RemoveExistingSocket(fileLink)
	assert.ErrorContains(t, err, "not a unix socket")
	assert.False(t, removed)
	assert.FileExists(t, fileLink)

	// Directory is never removed
	removed, _, err = RemoveExistingSocket(dir)
	assert.ErrorContains(t, err, "not a unix socket")
	assert.False(t, removed)

	// Socket still in use (e.g. the previous instance during a rolling update) is replaced and reported
	live := filepath.Join(dir, "live.sock")
	listener, err := net.Listen("unix", live)
	require.NoError(t, err)
	listener.(*net.UnixListener).SetUnlinkOnClose(false)
	defer listener.Close()
	removed, inUse, err = RemoveExistingSocket(live)
	assert.NoError(t, err)
	assert.True(t, removed)
	assert.True(t, inUse)
	assert.NoFileExists(t, live)

	// Stale socket left behind by a previous run is removed
	stale := filepath.Join(dir, "stale.sock")
	staleListener, err := net.Listen("unix", stale)
	require.NoError(t, err)
	staleListener.(*net.UnixListener).SetUnlinkOnClose(false)
	require.NoError(t, staleListener.Close())
	removed, inUse, err = RemoveExistingSocket(stale)
	assert.NoError(t, err)
	assert.True(t, removed)
	assert.False(t, inUse)
	assert.NoFileExists(t, stale)

	// Symlink to a socket is replaced like the socket itself
	target := filepath.Join(dir, "target.sock")
	targetListener, err := net.Listen("unix", target)
	require.NoError(t, err)
	targetListener.(*net.UnixListener).SetUnlinkOnClose(false)
	require.NoError(t, targetListener.Close())
	link := filepath.Join(dir, "link.sock")
	require.NoError(t, os.Symlink(target, link))
	removed, _, err = RemoveExistingSocket(link)
	assert.NoError(t, err)
	assert.True(t, removed)
	assert.NoFileExists(t, link)
}
