package controller

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestControllerClosePeriodicTasksReturnsJoinedErrorsWithoutPanicking(t *testing.T) {
	firstErr := errors.New("first close failed")
	secondErr := errors.New("second close failed")
	buffer := &bytes.Buffer{}
	logger := logrus.New()
	logger.SetOutput(buffer)
	logger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	controller := &Controller{
		logger: logrus.NewEntry(logger),
		tasks: []periodicTask{
			{tag: "first", Periodic: &recordingPeriodic{closeErr: firstErr}},
			{tag: "second", Periodic: &recordingPeriodic{closeErr: secondErr}},
		},
	}

	err := controller.closePeriodicTasks()
	if !errors.Is(err, firstErr) || !errors.Is(err, secondErr) {
		t.Fatalf("closePeriodicTasks() error = %v, want both close errors", err)
	}
	logOutput := buffer.String()
	if !strings.Contains(logOutput, "first periodic task close failed") ||
		!strings.Contains(logOutput, "second periodic task close failed") {
		t.Fatalf("closePeriodicTasks() log = %q, want both close failures", logOutput)
	}
}
