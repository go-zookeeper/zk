package zk

import (
	"context"
	"errors"
	"sync"
)

var ErrEventQueueClosed = errors.New("zk: event queue closed")

type Queue[T any] interface {
	// Next waits for a new element to be received until the context expires or the queue is closed.
	Next(ctx context.Context) (T, error)
	// Push adds the given element to the queue and notifies any in-flight calls to Next that a new element is
	// available.
	Push(e T)
	// Close functions like closing a channel. Subsequent calls to Next will drain whatever elements remain in the
	// buffer while subsequent calls to Push will panic. Once remaining elements are drained, Next will return
	// ErrEventQueueClosed.
	Close()
}

// EventQueue is added to preserve the old EventQueue type which had an equivalent interface, for backwards
// compatibility in method signatures.
type EventQueue = Queue[Event]

type ChanQueue[T any] chan T

func (c ChanQueue[T]) Next(ctx context.Context) (T, error) {
	select {
	case <-ctx.Done():
		var t T
		return t, ctx.Err()
	case e, ok := <-c:
		if !ok {
			var t T
			return t, ErrEventQueueClosed
		} else {
			return e, nil
		}
	}
}

func (c ChanQueue[T]) Push(e T) {
	c <- e
}

func (c ChanQueue[T]) Close() {
	close(c)
}

func newChanEventChannel() ChanQueue[Event] {
	return make(chan Event, 1)
}

type unlimitedEventQueue[T any] struct {
	lock       sync.Mutex
	newElement chan struct{}
	elements   []T
}

func NewUnlimitedQueue[T any]() Queue[T] {
	return &unlimitedEventQueue[T]{
		newElement: make(chan struct{}),
	}
}

func (q *unlimitedEventQueue[T]) Push(e T) {
	q.lock.Lock()
	defer q.lock.Unlock()

	if q.newElement == nil {
		// Panic like a closed channel
		panic("send on closed unlimited channel")
	}

	q.elements = append(q.elements, e)
	close(q.newElement)
	q.newElement = make(chan struct{})
}

func (q *unlimitedEventQueue[T]) Close() {
	q.lock.Lock()
	defer q.lock.Unlock()

	if q.newElement == nil {
		// Panic like a closed channel
		panic("close of closed Queue")
	}

	close(q.newElement)
	q.newElement = nil
}

func (q *unlimitedEventQueue[T]) Next(ctx context.Context) (T, error) {
	for {
		q.lock.Lock()
		if len(q.elements) > 0 {
			e := q.elements[0]
			q.elements = q.elements[1:]
			q.lock.Unlock()
			return e, nil
		}

		ch := q.newElement
		if ch == nil {
			q.lock.Unlock()
			var t T
			return t, ErrEventQueueClosed
		}
		q.lock.Unlock()

		select {
		case <-ctx.Done():
			var t T
			return t, ctx.Err()
		case <-ch:
			continue
		}
	}
}
