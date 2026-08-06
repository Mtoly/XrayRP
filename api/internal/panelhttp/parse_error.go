package panelhttp

type parseError struct {
	operation string
	cause     error
}

func (e *parseError) Error() string {
	return e.operation + " failed"
}

func (e *parseError) Unwrap() error {
	return e.cause
}

// NodeInfoParseError preserves the parser cause without exposing the panel payload.
func NodeInfoParseError(cause error) error {
	return &parseError{operation: "parse panel node info", cause: cause}
}

// UserListParseError preserves the parser cause without exposing the panel payload.
func UserListParseError(cause error) error {
	return &parseError{operation: "parse panel user list", cause: cause}
}
