package panelhttp

import (
	"errors"
	"strings"
	"testing"
)

func TestParseErrorsHideCauseTextAndPreserveIdentity(t *testing.T) {
	cause := errors.New("invalid value containing private-key-secret")
	tests := []struct {
		name string
		new  func(error) error
		want string
	}{
		{name: "node info", new: NodeInfoParseError, want: "parse panel node info failed"},
		{name: "user list", new: UserListParseError, want: "parse panel user list failed"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.new(cause)
			if got := err.Error(); got != tc.want {
				t.Fatalf("Error() = %q, want %q", got, tc.want)
			}
			if strings.Contains(err.Error(), "private-key-secret") {
				t.Fatalf("Error() exposed parser cause: %q", err)
			}
			if !errors.Is(err, cause) {
				t.Fatalf("errors.Is(error, cause) = false")
			}
		})
	}
}
