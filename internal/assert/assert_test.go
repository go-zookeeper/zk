package assert

import (
	"errors"
	"testing"
)

type call struct {
	name string
	args []interface{}
}

// fakeT is a fake implementation of TestingT.
// It records calls to its methods.
// Its methods are not safe for concurrent use.
type fakeT struct {
	calls []call
}

func (f *fakeT) Errorf(format string, args ...interface{}) {
	f.calls = append(f.calls, call{
		name: "Errorf",
		args: append([]interface{}{format}, args...),
	})
}

func (f *fakeT) Helper() {
	f.calls = append(f.calls, call{name: "Helper"})
}

func TestEqual(t *testing.T) {
	tests := []struct {
		name           string
		giveWant       interface{}
		giveGot        interface{}
		giveMsgAndArgs []interface{}
		want           []call
	}{
		{
			name:     "equal",
			giveWant: 1,
			giveGot:  1,
			want:     nil,
		},
		{
			name:     "not equal shallow",
			giveWant: 1,
			giveGot:  2,
			want: []call{
				{name: "Helper"},
				{name: "Errorf", args: []interface{}{"not equal: want: 1, got: 2"}},
			},
		},
		{
			name:     "not equal deep",
			giveWant: map[string]interface{}{"foo": struct{ bar string }{"baz"}},
			giveGot:  map[string]interface{}{"foo": struct{ bar string }{"foobar"}},
			want: []call{
				{name: "Helper"},
				{name: "Errorf", args: []interface{}{"not equal: want: map[foo:{bar:baz}], got: map[foo:{bar:foobar}]"}},
			},
		},
		{
			name:           "with message",
			giveWant:       1,
			giveGot:        2,
			giveMsgAndArgs: []interface{}{"user message"},
			want: []call{
				{name: "Helper"},
				{name: "Errorf", args: []interface{}{"not equal: want: 1, got: 2: user message"}},
			},
		},
		{
			name:           "with message and args",
			giveWant:       1,
			giveGot:        2,
			giveMsgAndArgs: []interface{}{"user message: %d %s", 1, "arg2"},
			want: []call{
				{name: "Helper"},
				{name: "Errorf", args: []interface{}{"not equal: want: 1, got: 2: user message: 1 arg2"}},
			},
		},
		{
			name:           "only args",
			giveWant:       1,
			giveGot:        2,
			giveMsgAndArgs: []interface{}{1, "arg2"},
			want: []call{
				{name: "Helper"},
				{name: "Errorf", args: []interface{}{"not equal: want: 1, got: 2: [1 arg2]"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f fakeT
			Equal(&f, tt.giveWant, tt.giveGot, tt.giveMsgAndArgs...)
			// Since we're asserting ourselves it might be possible to introduce a subtle bug.
			// However, the code is straightforward so it's not a big deal.
			Equal(t, tt.want, f.calls)
		})
	}
}

func TestNoError(t *testing.T) {
	tests := []struct {
		name           string
		giveErr        error
		giveMsgAndArgs []interface{}
		want           []call
	}{
		{
			name:    "no error",
			giveErr: nil,
			want:    nil,
		},
		{
			name:    "with error",
			giveErr: errors.New("foo"),
			want: []call{
				{name: "Helper"},
				{name: "Errorf", args: []interface{}{"unexpected error: foo"}},
			},
		},
		{
			name:           "with message",
			giveErr:        errors.New("foo"),
			giveMsgAndArgs: []interface{}{"user message"},
			want: []call{
				{name: "Helper"},
				{name: "Errorf", args: []interface{}{"unexpected error: foo: user message"}},
			},
		},
		{
			name:           "with message and args",
			giveErr:        errors.New("foo"),
			giveMsgAndArgs: []interface{}{"user message: %d %s", 1, "arg2"},
			want: []call{
				{name: "Helper"},
				{name: "Errorf", args: []interface{}{"unexpected error: foo: user message: 1 arg2"}},
			},
		},
		{
			name:           "only args",
			giveErr:        errors.New("foo"),
			giveMsgAndArgs: []interface{}{1, "arg2"},
			want: []call{
				{name: "Helper"},
				{name: "Errorf", args: []interface{}{"unexpected error: foo: [1 arg2]"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f fakeT
			NoError(&f, tt.giveErr, tt.giveMsgAndArgs...)
			Equal(t, tt.want, f.calls)
		})
	}
}
