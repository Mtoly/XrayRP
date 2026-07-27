package mylego

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func removeFile(path string) error {
	return removeFileWithRename(path, replaceFile)
}

func removeFileWithRename(path string, renameFile func(string, string) error) error {
	if renameFile == nil {
		renameFile = replaceFile
	}
	if err := rejectSymlinkPathComponents(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to remove non-regular certificate path %s", filepath.Base(path))
	}

	tombstone, err := stageFile(fileTransactionEntry{
		path: path,
		perm: filePerm,
	})
	if err != nil {
		return err
	}
	if err := renameFile(path, tombstone); err != nil {
		_ = os.Remove(tombstone)
		return err
	}

	// The target name is already durably removed on Windows by MoveFileExW
	// with WRITE_THROUGH. POSIX callers sync the directory after this returns.
	// A crash may leave only this reserved tombstone, which recovery removes.
	_ = os.Remove(tombstone)
	return nil
}
