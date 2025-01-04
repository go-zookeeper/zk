// Internal assertion library inspired by https://github.com/stretchr/testify.
// "A little copying is better than a little dependency." - https://go-proverbs.github.io.
// We don't want the library to have dependencies, so we write our own assertions.
package assert

import (
	"fmt"
	"reflect"
)

// TestingT is an interface wrapper around stdlib *testing.T.
type TestingT interface {
	Errorf(format string, args ...interface{})
	Helper()
}

// Equal asserts that expected is equal to actual.
func Equal(t TestingT, want, got interface{}, msgAndArgs ...interface{}) {
	if !reflect.DeepEqual(want, got) {
		fail(t, fmt.Sprintf("not equal: want: %+v, got: %+v", want, got), msgAndArgs)
	}
}

// NoError asserts that the error is nil.
func NoError(t TestingT, err error, msgAndArgs ...interface{}) {
	if err != nil {
		fail(t, fmt.Sprintf("unexpected error: %v", err), msgAndArgs)
	}
}

func fail(t TestingT, message string, msgAndArgs []interface{}) {
	t.Helper()
	userMessage := msgAndArgsToString(msgAndArgs)
	if userMessage != "" {
		message += ": " + userMessage
	}
	t.Errorf(message)
}

func msgAndArgsToString(msgAndArgs []interface{}) string {
	if len(msgAndArgs) == 0 {
		return ""
	}
	if len(msgAndArgs) == 1 {
		return fmt.Sprintf("%+v", msgAndArgs[0])
	}
	if format, ok := msgAndArgs[0].(string); ok {
		return fmt.Sprintf(format, msgAndArgs[1:]...)
	}
	return fmt.Sprintf("%+v", msgAndArgs)
}
