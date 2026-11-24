package utils

import (
	"fmt"
	"net"
	"os"
	"time"
)

func ReadFile(file string) (string, error) {
	_, err := os.Stat(file)
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// RemoveExistingSocket removes the unix socket left at path by a previous (or still running) instance so the server
// can listen on it again. It reports whether a socket was removed and whether it was still accepting connections.
// Anything that is not a socket (e.g. a regular file or a directory) is never removed.
func RemoveExistingSocket(path string) (removed bool, inUse bool, err error) {
	// stat follows symlinks, a symlink to a socket is replaced like the socket itself
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}

	if info.Mode().Type() != os.ModeSocket {
		return false, false, fmt.Errorf("refusing to remove %s, it is not a unix socket", path)
	}

	conn, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		conn.Close()
		inUse = true
	}

	if err := os.Remove(path); err != nil {
		return false, inUse, err
	}

	return true, inUse, nil
}
