package zk

import (
	"fmt"
	"testing"
)

// TestErrCodeToError verifies that every server error code known to the
// client (including the ones added for
// https://github.com/go-zookeeper/zk/issues/54) round-trips through
// ErrCode.toError() to its documented sentinel error, and that the
// resulting error's message survives an Error() call unchanged.
func TestErrCodeToError(t *testing.T) {
	tests := []struct {
		code ErrCode
		err  error
	}{
		{0, nil},
		{errSystemError, ErrSystemError},
		{errRuntimeInconsistency, ErrRuntimeInconsistency},
		{errDataInconsistency, ErrDataInconsistency},
		{errConnectionLoss, ErrConnectionLoss},
		{errMarshallingError, ErrMarshallingError},
		{errUnimplemented, ErrUnimplemented},
		{errOperationTimeout, ErrOperationTimeout},
		{errBadArguments, ErrBadArguments},
		{errUnknownSession, ErrUnknownSession},
		{errNewConfigNoQuorum, ErrNewConfigNoQuorum},
		{errReconfigInProgress, ErrReconfigInProgress},
		{errAPIError, ErrAPIError},
		{errNoNode, ErrNoNode},
		{errNoAuth, ErrNoAuth},
		{errBadVersion, ErrBadVersion},
		{errNoChildrenForEphemerals, ErrNoChildrenForEphemerals},
		{errNodeExists, ErrNodeExists},
		{errNotEmpty, ErrNotEmpty},
		{errSessionExpired, ErrSessionExpired},
		{errInvalidCallback, ErrInvalidCallback},
		{errInvalidAcl, ErrInvalidACL},
		{errAuthFailed, ErrAuthFailed},
		{errClosing, ErrClosing},
		{errNothing, ErrNothing},
		{errSessionMoved, ErrSessionMoved},
		{errNotReadOnly, ErrNotReadOnly},
		{errEphemeralOnLocalSession, ErrEphemeralOnLocalSession},
		{errNoWatcher, ErrNoWatcher},
		{errRequestTimeout, ErrRequestTimeout},
		{errZReconfigDisabled, ErrReconfigDisabled},
		{errSessionClosedRequireSaslAuth, ErrSessionClosedRequireSaslAuth},
		{errQuotaExceeded, ErrQuotaExceeded},
		{errThrottled, ErrThrottled},
	}

	seenCodes := make(map[ErrCode]bool, len(tests))
	for _, tt := range tests {
		if seenCodes[tt.code] {
			t.Errorf("duplicate test case for code %d", tt.code)
		}
		seenCodes[tt.code] = true

		got := tt.code.toError()
		if got != tt.err {
			t.Errorf("ErrCode(%d).toError() = %v, want %v", tt.code, got, tt.err)
			continue
		}
		if got == nil {
			continue
		}
		if got.Error() != tt.err.Error() {
			t.Errorf("ErrCode(%d).toError().Error() = %q, want %q", tt.code, got.Error(), tt.err.Error())
		}
	}
}

// TestErrCodeToErrorUnknown verifies codes with no mapping fall back to the
// generic "unknown error" message instead of panicking or matching a wrong
// sentinel.
func TestErrCodeToErrorUnknown(t *testing.T) {
	unmapped := ErrCode(-9999)
	err := unmapped.toError()
	want := "unknown error: -9999"
	if err == nil || err.Error() != want {
		t.Errorf("ErrCode(-9999).toError() = %v, want error %q", err, want)
	}
}

func TestModeString(t *testing.T) {
	if fmt.Sprintf("%v", ModeUnknown) != "unknown" {
		t.Errorf("unknown value should be 'unknown'")
	}

	if fmt.Sprintf("%v", ModeLeader) != "leader" {
		t.Errorf("leader value should be 'leader'")
	}

	if fmt.Sprintf("%v", ModeFollower) != "follower" {
		t.Errorf("follower value should be 'follower'")
	}

	if fmt.Sprintf("%v", ModeStandalone) != "standalone" {
		t.Errorf("standlone value should be 'standalone'")
	}
}
