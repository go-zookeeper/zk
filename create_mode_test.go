package zk

import (
	"strings"
	"testing"
)

func TestParseCreateMode(t *testing.T) {
	changeDetectorTests := []struct {
		name         string
		flag         int32
		wantIntValue int32
	}{
		{"valid flag createmode 0 persistant", FlagPersistent, 0},
		{"ephemeral", FlagEphemeral, 1},
		{"sequential", FlagSequence, 2},
		{"ephemeral sequential", FlagEphemeralSequential, 3},
		{"container", FlagContainer, 4},
		{"ttl", FlagTTL, 5},
		{"persistentSequential w/TTL", FlagPersistentSequentialWithTTL, 6},
	}
	for _, tt := range changeDetectorTests {
		t.Run(tt.name, func(t *testing.T) {
			cm, err := parseCreateMode(tt.flag)
			requireNoErrorf(t, err)
			if cm.toFlag() != tt.wantIntValue {
				// change detector test for enum values.
				t.Fatalf("createmode value of flag; want: %v, got: %v", cm.toFlag(), tt.wantIntValue)
			}
		})
	}

	t.Run("failed to parse", func(t *testing.T) {
		cm, err := parseCreateMode(-123)
		if err == nil {
			t.Fatalf("error expected, got: %v", cm)
		}
		if !strings.Contains(err.Error(), "invalid flag value") {
			t.Fatalf("unexpected error value: %v", err)
		}
	})

}
