package common

import "testing"

func TestSetShowErrorDetails(t *testing.T) {
	previous := ShowErrorDetails()
	t.Cleanup(func() { SetShowErrorDetails(previous) })
	t.Setenv(ShowErrorDetailsEnv, "")

	SetShowErrorDetails(false)
	if ShowErrorDetails() {
		t.Fatal("expected detailed error logging to be disabled")
	}

	SetShowErrorDetails(true)
	if !ShowErrorDetails() {
		t.Fatal("expected detailed error logging to be enabled")
	}
}

func TestSetShowErrorDetailsHonorsEnvironmentOverride(t *testing.T) {
	previous := ShowErrorDetails()
	t.Cleanup(func() { SetShowErrorDetails(previous) })
	t.Setenv(ShowErrorDetailsEnv, "true")

	SetShowErrorDetails(false)
	if !ShowErrorDetails() {
		t.Fatal("expected environment override to enable detailed error logging")
	}
}
