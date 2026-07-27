package mylego

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

var certificateOperationMu sync.Mutex

type environmentValue struct {
	key     string
	value   string
	existed bool
}

func executeCertificateOperation(dnsEnv map[string]string, operation func() error) (err error) {
	certificateOperationMu.Lock()
	defer certificateOperationMu.Unlock()

	restore, err := applyDNSEnvironment(dnsEnv)
	if err != nil {
		return err
	}
	defer func() {
		panicErr := panicValueError(recover())
		err = errors.Join(err, panicErr, restore())
	}()

	if operation == nil {
		return errors.New("certificate operation is nil")
	}
	return operation()
}

func applyDNSEnvironment(values map[string]string) (func() error, error) {
	normalized := make(map[string]string, len(values))
	for key, value := range values {
		envKey := strings.ToUpper(key)
		if !isAllowedDNSEnvKey(envKey) {
			log.Warnf("Skipping disallowed DNS env key: %s", envKey)
			continue
		}
		if previous, exists := normalized[envKey]; exists && previous != value {
			return func() error { return nil }, fmt.Errorf("duplicate DNS environment key after normalization: %s", envKey)
		}
		normalized[envKey] = value
	}

	keys := make([]string, 0, len(normalized))
	for key := range normalized {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	snapshot := make([]environmentValue, 0, len(keys))
	restore := func() error {
		var restoreErrors []error
		for i := len(snapshot) - 1; i >= 0; i-- {
			item := snapshot[i]
			var err error
			if item.existed {
				err = os.Setenv(item.key, item.value)
			} else {
				err = os.Unsetenv(item.key)
			}
			if err != nil {
				restoreErrors = append(restoreErrors, fmt.Errorf("restore DNS environment key %s: %w", item.key, err))
			}
		}
		return errors.Join(restoreErrors...)
	}

	for _, key := range keys {
		oldValue, existed := os.LookupEnv(key)
		snapshot = append(snapshot, environmentValue{key: key, value: oldValue, existed: existed})
		if err := os.Setenv(key, normalized[key]); err != nil {
			return func() error { return nil }, errors.Join(
				fmt.Errorf("set DNS environment key %s: %w", key, err),
				restore(),
			)
		}
	}
	return restore, nil
}

func panicValueError(value any) error {
	switch typed := value.(type) {
	case nil:
		return nil
	case error:
		return typed
	case string:
		return errors.New(typed)
	default:
		return fmt.Errorf("certificate operation panicked with %T", value)
	}
}
