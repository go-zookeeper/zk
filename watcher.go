package zk

import (
	"context"
	"sync"
	"time"
)

func newFireOnceWatcher() *fireOnceWatcher {
	return &fireOnceWatcher{
		ch: make(chan Event, 2), // Buffer to hold 1 watch event + 1 close event.
	}
}

// fireOnceWatcher is an implementation of watcher that fires a single watch event (ie: for GetW, ExistsW, ChildrenW).
type fireOnceWatcher struct {
	ch        chan Event
	closeOnce sync.Once
}

func (w *fireOnceWatcher) eventChan() <-chan Event {
	return w.ch
}

func (w *fireOnceWatcher) notify(ev Event) (ok bool) {
	// This is a bit ugly, but it's not impossible for a watcher to be notified after it's been closed.
	// It's a compromise that allows us to have finer-grained locking in the connection's receive loop.
	// It's also not worth synchronizing notify() and close(), since this is a very rare case.
	defer func() {
		_ = recover() // Ignore panics from closed channel.
	}()

	w.ch <- ev
	return true
}

func (w *fireOnceWatcher) close() {
	w.closeOnce.Do(func() {
		close(w.ch)
	})
}

func newPersistentWatcher(stallCallback func()) *persistentWatcher {
	return &persistentWatcher{
		pump: NewPump[Event](stallCallback),
	}
}

// persistentWatcher is an implementation of watcher for persistent watches.
type persistentWatcher struct {
	pump *Pump[Event]
}

func (w *persistentWatcher) eventChan() <-chan Event {
	return w.pump.OutChan()
}

func (w *persistentWatcher) notify(ev Event) bool {
	return w.pump.Give(context.Background(), ev)
}

func (w *persistentWatcher) close() {
	// Closing input will allow the pump to drain and stop naturally, as long as output is consumed.
	w.pump.CloseInput() // Idempotent.

	// If output is not consumed, then the pump may not be able to stop, causing a goroutine leak.
	// To protect against this, we'll wait up to 5 minutes for the pump to stop, after which we force it.
	if !w.pump.IsStopRequested() {
		go func(p *Pump[Event]) { // Monitor the pump in a new goroutine.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			if p.WaitUntilStopped(ctx) == context.DeadlineExceeded {
				p.Stop() // Force stop; idempotent.
			}
		}(w.pump)
	}
}
