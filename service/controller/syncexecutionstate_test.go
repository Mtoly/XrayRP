package controller

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestControllerRecordSyncExecutionResult_OmitsErrorDetailsByDefault(t *testing.T) {
	var output bytes.Buffer
	logger := log.New()
	logger.SetOutput(&output)
	controller := &Controller{
		config:             &Config{},
		logger:             log.NewEntry(logger),
		syncExecutionState: newSyncExecutionState(),
	}
	action := newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{Trigger: "users_changed"})

	controller.recordSyncExecutionResult(action, errors.New("token=secret-value"))

	logged := output.String()
	for _, safeValue := range []string{string(action.Type), string(action.Source), action.Metadata.Trigger} {
		if !strings.Contains(logged, safeValue) {
			t.Fatalf("log missing safe action metadata %q: %s", safeValue, logged)
		}
	}
	if strings.Contains(logged, "secret-value") {
		t.Fatalf("log exposed error details: %s", logged)
	}
}

func TestControllerRecordSyncExecutionResult_ShowsAllowedErrorDetails(t *testing.T) {
	var output bytes.Buffer
	logger := log.New()
	logger.SetOutput(&output)
	controller := &Controller{
		config:             &Config{ShowErrorDetails: true},
		logger:             log.NewEntry(logger),
		syncExecutionState: newSyncExecutionState(),
	}

	controller.recordSyncExecutionResult(
		newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{Trigger: "users_changed"}),
		errors.New("diagnostic detail"),
	)

	if !strings.Contains(output.String(), "diagnostic detail") {
		t.Fatalf("allowed error details missing from log: %s", output.String())
	}
}
