//go:build !windows

package mylego

import "os"

func replaceFile(source, target string) error {
	return os.Rename(source, target)
}
