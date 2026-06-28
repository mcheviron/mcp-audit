package safeio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func ReadFile(path string) ([]byte, error) {
	cleaned, err := validatePath(path)
	if err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(resolved)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

func ExecShell(ctx context.Context, command string) *exec.Cmd {
	if command == "" {
		return nil
	}
	return exec.CommandContext(ctx, "sh", "-c", command)
}

func validatePath(path string) (string, error) {
	if path == "" {
		return "", errors.New("empty path")
	}
	if strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("path contains null byte")
	}
	return filepath.Clean(path), nil
}
