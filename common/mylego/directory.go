package mylego

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func createDirectoryAllDurable(path string, perm os.FileMode) error {
	return createDirectoryAllDurableWithSync(path, perm, syncDirectory)
}

func createDirectoryAllDurableWithSync(
	path string,
	perm os.FileMode,
	syncDir func(string) error,
) error {
	if syncDir == nil {
		syncDir = syncDirectory
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	var missing []string
	for current := absolutePath; ; current = filepath.Dir(current) {
		info, statErr := os.Lstat(current)
		switch {
		case statErr == nil && info.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("refusing certificate directory symbolic link %s", filepath.Base(current))
		case statErr == nil && !info.IsDir():
			return fmt.Errorf("certificate directory path %s is not a directory", filepath.Base(current))
		case statErr == nil:
			goto createMissing
		case !errors.Is(statErr, os.ErrNotExist):
			return fmt.Errorf("inspect certificate directory %s: %w", filepath.Base(current), statErr)
		default:
			missing = append(missing, current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("certificate directory root %s does not exist", current)
		}
	}

createMissing:
	for i := len(missing) - 1; i >= 0; i-- {
		current := missing[i]
		if err := os.Mkdir(current, perm); err != nil {
			return fmt.Errorf("create certificate directory %s: %w", filepath.Base(current), err)
		}
		if err := syncDir(current); err != nil {
			return fmt.Errorf("sync new certificate directory %s: %w", filepath.Base(current), err)
		}
		parent := filepath.Dir(current)
		if err := syncDir(parent); err != nil {
			return fmt.Errorf("sync parent of certificate directory %s: %w", filepath.Base(current), err)
		}
	}
	return nil
}
