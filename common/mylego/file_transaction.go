package mylego

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	fileTransactionJournalName = ".xrayrp-certificate-transaction.json"
	fileTransactionTempPrefix  = ".xrayrp-certificate-transaction-"
)

var fileTransactionMu sync.Mutex

type fileTransactionEntry struct {
	path   string
	data   []byte
	perm   os.FileMode
	remove bool
}

type fileTransactionSnapshot struct {
	existed bool
	data    []byte
	perm    os.FileMode
}

type stagedFile struct {
	entry    fileTransactionEntry
	snapshot fileTransactionSnapshot
	tempPath string
}

type fileTransactionJournal struct {
	Committed bool                          `json:"committed"`
	Entries   []fileTransactionJournalEntry `json:"entries"`
}

type fileTransactionJournalEntry struct {
	Name          string      `json:"name"`
	TempName      string      `json:"temp_name,omitempty"`
	Existed       bool        `json:"existed"`
	Data          []byte      `json:"data,omitempty"`
	Perm          os.FileMode `json:"perm,omitempty"`
	Remove        bool        `json:"remove,omitempty"`
	PublishedHash string      `json:"published_hash,omitempty"`
}

func writeFileTransaction(entries []fileTransactionEntry, renameFile func(string, string) error) error {
	return writeFileTransactionWithSync(entries, renameFile, syncDirectory)
}

func writeFileTransactionWithSync(
	entries []fileTransactionEntry,
	renameFile func(string, string) error,
	syncDir func(string) error,
) error {
	return writeFileTransactionWithOperations(entries, renameFile, replaceFile, syncDir)
}

func writeFileTransactionWithOperations(
	entries []fileTransactionEntry,
	renameFile func(string, string) error,
	replaceJournalFile func(string, string) error,
	syncDir func(string) error,
) error {
	fileTransactionMu.Lock()
	defer fileTransactionMu.Unlock()

	if len(entries) == 0 {
		return nil
	}
	if renameFile == nil {
		renameFile = replaceFile
	}
	if replaceJournalFile == nil {
		replaceJournalFile = replaceFile
	}
	if syncDir == nil {
		syncDir = syncDirectory
	}
	transactionDir, normalizedEntries, err := normalizeTransactionEntries(entries)
	if err != nil {
		return err
	}
	if err := recoverFileTransactionLocked(transactionDir); err != nil {
		return err
	}

	staged := make([]stagedFile, 0, len(entries))
	cleanup := func() error {
		var cleanupErrors []error
		for i := range staged {
			if staged[i].tempPath == "" {
				continue
			}
			if err := os.Remove(staged[i].tempPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				cleanupErrors = append(cleanupErrors, err)
			}
		}
		return errors.Join(cleanupErrors...)
	}

	for _, entry := range normalizedEntries {
		snapshot, err := snapshotRegularFile(entry.path)
		if err != nil {
			return errors.Join(err, cleanup())
		}
		var tempPath string
		if !entry.remove {
			tempPath, err = stageFile(entry)
			if err != nil {
				return errors.Join(err, cleanup())
			}
		}
		staged = append(staged, stagedFile{
			entry:    entry,
			snapshot: snapshot,
			tempPath: tempPath,
		})
	}

	journal := journalFromStagedFiles(staged)
	if _, err := writeFileTransactionJournal(transactionDir, journal, replaceJournalFile, syncDir); err != nil {
		return errors.Join(err, cleanup())
	}

	committed := 0
	for i := range staged {
		var publishErr error
		if staged[i].entry.remove {
			publishErr = removeFileWithRename(staged[i].entry.path, renameFile)
		} else {
			publishErr = renameFile(staged[i].tempPath, staged[i].entry.path)
		}
		if publishErr != nil {
			rollbackErr := rollbackFiles(staged[:committed], renameFile)
			journalErr := finishFailedFileTransaction(transactionDir, rollbackErr, syncDir)
			return errors.Join(
				fmt.Errorf("publish %s: %w", filepath.Base(staged[i].entry.path), publishErr),
				rollbackErr,
				journalErr,
				cleanup(),
			)
		}
		staged[i].tempPath = ""
		committed++
		if err := syncDir(transactionDir); err != nil {
			rollbackErr := rollbackFiles(staged[:committed], renameFile)
			journalErr := finishFailedFileTransaction(transactionDir, rollbackErr, syncDir)
			return errors.Join(
				fmt.Errorf("sync certificate directory after publishing %s: %w", filepath.Base(staged[i].entry.path), err),
				rollbackErr,
				journalErr,
				cleanup(),
			)
		}
	}

	committedJournal := journal
	committedJournal.Committed = true
	committedJournal.Entries = append([]fileTransactionJournalEntry(nil), journal.Entries...)
	journalPublished, err := writeFileTransactionJournal(
		transactionDir,
		committedJournal,
		replaceJournalFile,
		syncDir,
	)
	if err != nil {
		var restoreJournalErr error
		if journalPublished {
			_, restoreJournalErr = writeFileTransactionJournal(
				transactionDir,
				journal,
				replaceJournalFile,
				syncDir,
			)
			if restoreJournalErr != nil {
				restoreJournalErr = fmt.Errorf("restore recoverable certificate transaction journal: %w", restoreJournalErr)
			}
		}
		rollbackErr := rollbackFiles(staged[:committed], renameFile)
		journalErr := finishFailedFileTransaction(transactionDir, rollbackErr, syncDir)
		return errors.Join(
			fmt.Errorf("mark certificate transaction committed: %w", err),
			restoreJournalErr,
			rollbackErr,
			journalErr,
			cleanup(),
		)
	}
	_ = removeFileTransactionJournalWithSync(transactionDir, syncDir)
	return nil
}

func normalizeTransactionEntries(entries []fileTransactionEntry) (string, []fileTransactionEntry, error) {
	normalized := make([]fileTransactionEntry, len(entries))
	var transactionDir string
	seen := make(map[string]struct{}, len(entries))
	for i, entry := range entries {
		absolutePath, err := filepath.Abs(entry.path)
		if err != nil {
			return "", nil, err
		}
		dir := filepath.Dir(absolutePath)
		if transactionDir == "" {
			transactionDir = dir
		} else if dir != transactionDir {
			return "", nil, errors.New("certificate transaction entries must share one directory")
		}
		if _, exists := seen[absolutePath]; exists {
			return "", nil, fmt.Errorf("duplicate certificate transaction path %s", filepath.Base(absolutePath))
		}
		name := filepath.Base(absolutePath)
		lowerName := strings.ToLower(name)
		if lowerName == strings.ToLower(fileTransactionJournalName) ||
			strings.HasPrefix(lowerName, strings.ToLower(fileTransactionTempPrefix)) {
			return "", nil, fmt.Errorf("certificate transaction target uses reserved path %s", name)
		}
		seen[absolutePath] = struct{}{}
		normalized[i] = entry
		normalized[i].path = absolutePath
	}
	return transactionDir, normalized, nil
}

func journalFromStagedFiles(files []stagedFile) fileTransactionJournal {
	journal := fileTransactionJournal{
		Entries: make([]fileTransactionJournalEntry, 0, len(files)),
	}
	for _, file := range files {
		tempName := ""
		if file.tempPath != "" {
			tempName = filepath.Base(file.tempPath)
		}
		publishedHash := ""
		if !file.entry.remove {
			publishedHash = fmt.Sprintf("%x", sha256.Sum256(file.entry.data))
		}
		journal.Entries = append(journal.Entries, fileTransactionJournalEntry{
			Name:          filepath.Base(file.entry.path),
			TempName:      tempName,
			Existed:       file.snapshot.existed,
			Data:          file.snapshot.data,
			Perm:          file.snapshot.perm,
			Remove:        file.entry.remove,
			PublishedHash: publishedHash,
		})
	}
	return journal
}

func writeFileTransactionJournal(
	dir string,
	journal fileTransactionJournal,
	replaceJournalFile func(string, string) error,
	syncDir func(string) error,
) (published bool, err error) {
	data, err := json.Marshal(journal)
	if err != nil {
		return false, err
	}
	journalPath := filepath.Join(dir, fileTransactionJournalName)
	tempPath, err := stageFile(fileTransactionEntry{
		path: journalPath,
		data: data,
		perm: filePerm,
	})
	if err != nil {
		return false, err
	}
	if err := replaceJournalFile(tempPath, journalPath); err != nil {
		_ = os.Remove(tempPath)
		return false, err
	}
	if err := syncDir(dir); err != nil {
		return true, err
	}
	return true, nil
}

func finishFailedFileTransaction(dir string, rollbackErr error, syncDir func(string) error) error {
	if rollbackErr != nil {
		return nil
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("sync rolled-back certificate transaction: %w", err)
	}
	return removeFileTransactionJournalWithSync(dir, syncDir)
}

func removeFileTransactionJournal(dir string) error {
	return removeFileTransactionJournalWithSync(dir, syncDirectory)
}

func removeFileTransactionJournalWithSync(dir string, syncDir func(string) error) error {
	journalPath := filepath.Join(dir, fileTransactionJournalName)
	if err := removeFile(journalPath); err != nil {
		return err
	}
	return syncDir(dir)
}

func recoverFileTransaction(dir string) error {
	fileTransactionMu.Lock()
	defer fileTransactionMu.Unlock()
	return recoverFileTransactionLocked(dir)
}

func recoverFileTransactionLocked(dir string) error {
	journalPath := filepath.Join(dir, fileTransactionJournalName)
	if err := rejectSymlinkPathComponents(journalPath); err != nil {
		return err
	}
	info, err := os.Lstat(journalPath)
	if errors.Is(err, os.ErrNotExist) {
		return removeOrphanedFileTransactionTemps(dir)
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("certificate transaction journal is not a regular file")
	}
	data, err := os.ReadFile(journalPath)
	if err != nil {
		return err
	}
	var journal fileTransactionJournal
	if err := json.Unmarshal(data, &journal); err != nil {
		return fmt.Errorf("parse certificate transaction journal: %w", err)
	}
	if journal.Committed {
		matches, matchErr := committedFileTransactionMatches(dir, journal.Entries)
		if matchErr != nil {
			return matchErr
		}
		if matches {
			// Cleanup cannot invalidate an already complete published set.
			_ = removeJournalTemps(dir, journal.Entries)
			_ = removeFileTransactionJournal(dir)
			_ = removeOrphanedFileTransactionTemps(dir)
			return nil
		}
	}

	var restoreErrors []error
	for i := len(journal.Entries) - 1; i >= 0; i-- {
		entry := journal.Entries[i]
		target, validateErr := journalEntryPath(dir, entry.Name)
		if validateErr != nil {
			restoreErrors = append(restoreErrors, validateErr)
			continue
		}
		if !entry.Existed {
			if removeErr := removeFile(target); removeErr != nil {
				restoreErrors = append(restoreErrors, fmt.Errorf("remove interrupted %s: %w", entry.Name, removeErr))
			}
			continue
		}
		tempPath, stageErr := stageFile(fileTransactionEntry{
			path: target,
			data: entry.Data,
			perm: entry.Perm,
		})
		if stageErr != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("stage recovery %s: %w", entry.Name, stageErr))
			continue
		}
		if replaceErr := replaceFile(tempPath, target); replaceErr != nil {
			_ = os.Remove(tempPath)
			restoreErrors = append(restoreErrors, fmt.Errorf("recover %s: %w", entry.Name, replaceErr))
		}
	}
	if err := errors.Join(restoreErrors...); err != nil {
		return err
	}
	if err := syncDirectory(dir); err != nil {
		return err
	}
	if err := removeJournalTemps(dir, journal.Entries); err != nil {
		return err
	}
	if err := removeFileTransactionJournal(dir); err != nil {
		return err
	}
	return removeOrphanedFileTransactionTemps(dir)
}

func committedFileTransactionMatches(dir string, entries []fileTransactionJournalEntry) (bool, error) {
	hasRecoveryEvidence := false
	for _, entry := range entries {
		if entry.Existed ||
			len(entry.Data) > 0 ||
			entry.Perm != 0 ||
			entry.Remove ||
			entry.PublishedHash != "" {
			hasRecoveryEvidence = true
			break
		}
	}
	if !hasRecoveryEvidence {
		return true, nil
	}

	for _, entry := range entries {
		target, err := journalEntryPath(dir, entry.Name)
		if err != nil {
			return false, err
		}
		info, err := os.Lstat(target)
		if entry.Remove {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return false, err
			}
			return false, nil
		}
		if entry.PublishedHash == "" || errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !info.Mode().IsRegular() {
			return false, nil
		}
		data, err := os.ReadFile(target)
		if err != nil {
			return false, err
		}
		if fmt.Sprintf("%x", sha256.Sum256(data)) != entry.PublishedHash {
			return false, nil
		}
	}
	return true, nil
}

func journalEntryPath(dir, name string) (string, error) {
	if name == "" ||
		name == "." ||
		name == ".." ||
		filepath.Base(name) != name ||
		strings.ContainsAny(name, `/\`) ||
		strings.ContainsRune(name, '\x00') {
		return "", fmt.Errorf("certificate transaction journal contains invalid path %q", name)
	}
	return filepath.Join(dir, name), nil
}

func removeJournalTemps(dir string, entries []fileTransactionJournalEntry) error {
	var errs []error
	for _, entry := range entries {
		if entry.TempName == "" {
			continue
		}
		tempPath, err := journalEntryPath(dir, entry.TempName)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := os.Remove(tempPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func removeOrphanedFileTransactionTemps(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}

	removed := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), fileTransactionTempPrefix) {
			continue
		}
		if entry.IsDir() {
			return fmt.Errorf("reserved certificate transaction path %s is a directory", entry.Name())
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		removed = true
	}
	if !removed {
		return nil
	}
	return syncDirectory(dir)
}

func snapshotRegularFile(path string) (fileTransactionSnapshot, error) {
	if err := rejectSymlinkPathComponents(path); err != nil {
		return fileTransactionSnapshot{}, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fileTransactionSnapshot{}, nil
	}
	if err != nil {
		return fileTransactionSnapshot{}, fmt.Errorf("inspect %s: %w", filepath.Base(path), err)
	}
	if !info.Mode().IsRegular() {
		return fileTransactionSnapshot{}, fmt.Errorf("refusing to replace non-regular certificate path %s", filepath.Base(path))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fileTransactionSnapshot{}, fmt.Errorf("snapshot %s: %w", filepath.Base(path), err)
	}
	return fileTransactionSnapshot{
		existed: true,
		data:    data,
		perm:    info.Mode().Perm(),
	}, nil
}

func stageFile(entry fileTransactionEntry) (string, error) {
	if err := rejectSymlinkPathComponents(entry.path); err != nil {
		return "", err
	}
	dir := filepath.Dir(entry.path)
	if err := createDirectoryAllDurable(dir, 0o700); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(dir, fileTransactionTempPrefix)
	if err != nil {
		return "", err
	}
	tempPath := file.Name()
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(tempPath)
		}
	}()

	if err := file.Chmod(entry.perm); err != nil {
		return "", err
	}
	if _, err := file.Write(entry.data); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	remove = false
	return tempPath, nil
}

func validateExistingRegularFile(path string) error {
	if err := rejectSymlinkPathComponents(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("certificate path %s is not a regular file", filepath.Base(path))
	}
	return nil
}

func rejectSymlinkPathComponents(path string) error {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for current := filepath.Dir(absolutePath); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		switch {
		case err == nil && info.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("refusing certificate path beneath symbolic link %s", filepath.Base(current))
		case err == nil && !info.IsDir():
			return fmt.Errorf("certificate parent path %s is not a directory", filepath.Base(current))
		case err != nil && !errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("inspect certificate parent path %s: %w", filepath.Base(current), err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

func rollbackFiles(files []stagedFile, renameFile func(string, string) error) error {
	var rollbackErrors []error
	for i := len(files) - 1; i >= 0; i-- {
		file := files[i]
		if !file.snapshot.existed {
			if err := removeFileWithRename(file.entry.path, renameFile); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("remove new %s: %w", filepath.Base(file.entry.path), err))
			}
			continue
		}
		tempPath, err := stageFile(fileTransactionEntry{
			path: file.entry.path,
			data: file.snapshot.data,
			perm: file.snapshot.perm,
		})
		if err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("stage rollback %s: %w", filepath.Base(file.entry.path), err))
			continue
		}
		if err := renameFile(tempPath, file.entry.path); err != nil {
			_ = os.Remove(tempPath)
			rollbackErrors = append(rollbackErrors, fmt.Errorf("restore %s: %w", filepath.Base(file.entry.path), err))
		}
	}
	return errors.Join(rollbackErrors...)
}
