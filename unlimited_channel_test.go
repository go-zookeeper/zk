//go:build go1.18

package zk

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

func newEvent(i int) Event {
	return Event{Path: fmt.Sprintf("/%d", i)}
}

func TestUnlimitedChannel(t *testing.T) {
	names := []string{"notClosedAfterPushes", "closeAfterPushes"}
	for i, closeAfterPushes := range []bool{false, true} {
		t.Run(names[i], func(t *testing.T) {
			ch := NewUnlimitedQueue[Event]()
			const eventCount = 10

			// check that elements can be pushed without consumers
			for i := 0; i < eventCount; i++ {
				ch.Push(newEvent(i))
			}
			if closeAfterPushes {
				ch.Close()
			}

			for events := 0; events < eventCount; events++ {
				actual, err := ch.Next(context.Background())
				if err != nil {
					t.Fatalf("Unexpected error returned from Next (events %d): %+v", events, err)
				}
				expected := newEvent(events)
				if !reflect.DeepEqual(actual, expected) {
					t.Fatalf("Did not receive expected event from queue: actual %+v expected %+v", actual, expected)
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*10)
			t.Cleanup(cancel)

			_, err := ch.Next(ctx)
			if closeAfterPushes {
				if err != ErrEventQueueClosed {
					t.Fatalf("Did not receive expected error (%v) from Next: %v", ErrEventQueueClosed, err)
				}
			} else {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("Next did not exit with cancelled context: %+v", err)
				}
			}
		})
	}
	t.Run("interleaving", func(t *testing.T) {
		ch := NewUnlimitedQueue[Event]()

		for i := 0; i < 10; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*10)
			t.Cleanup(cancel)

			expected := newEvent(i)

			ctx = &customContext{
				Context: ctx,
				f: func() {
					ch.Push(expected)
				},
			}

			actual, err := ch.Next(ctx)
			if err != nil {
				t.Fatalf("Received unexpected error from Next: %+v", err)
			}
			if !reflect.DeepEqual(expected, actual) {
				t.Fatalf("Unexpected event received from Next (expected %+v, actual %+v", expected, actual)
			}
		}
	})
	t.Run("multiple consumers", func(t *testing.T) {
		ch := NewUnlimitedQueue[Event]()
		for i := 0; i < 20; i++ {
			ch.Push(newEvent(i))
		}
		ch.Close()
		var wg sync.WaitGroup
		wg.Add(20)
		for i := 0; i < 5; i++ {
			go func() {
				for {
					_, err := ch.Next(context.Background())
					if errors.Is(err, ErrEventQueueClosed) {
						return
					}
					requireNoErrorf(t, err)
					wg.Done()
				}
			}()
		}
		wg.Wait()
	})
}

type customContext struct {
	context.Context
	f func()
}

func (c *customContext) Done() <-chan struct{} {
	c.f()
	return c.Context.Done()
}
