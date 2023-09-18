package zk

import (
	"context"
	"errors"
	"sync"
)

var ErrEventQueueClosed = errors.New("zk: event queue closed")

type EventQueue interface {
	Next(ctx context.Context) (Event, error)
	push(e Event)
	close()
}

type chanEventQueue chan Event

func (c chanEventQueue) Next(ctx context.Context) (Event, error) {
	select {
	case <-ctx.Done():
		return Event{}, ctx.Err()
	case e, ok := <-c:
		if !ok {
			return Event{}, ErrEventQueueClosed
		} else {
			return e, nil
		}
	}
}

func (c chanEventQueue) push(e Event) {
	c <- e
}

func (c chanEventQueue) close() {
	close(c)
}

func newChanEventChannel() chanEventQueue {
	return make(chan Event, 1)
}

type unlimitedEventQueue struct {
	lock     sync.Mutex
	newEvent chan struct{}
	events   []Event
}

func newUnlimitedEventQueue() *unlimitedEventQueue {
	return &unlimitedEventQueue{
		newEvent: make(chan struct{}),
	}
}

func (q *unlimitedEventQueue) push(e Event) {
	q.lock.Lock()
	defer q.lock.Unlock()

	if q.newEvent == nil {
		// Panic like a closed channel
		panic("send on closed unlimited channel")
	}

	q.events = append(q.events, e)
	close(q.newEvent)
	q.newEvent = make(chan struct{})
}

func (q *unlimitedEventQueue) close() {
	q.lock.Lock()
	defer q.lock.Unlock()

	if q.newEvent == nil {
		// Panic like a closed channel
		panic("close of closed EventQueue")
	}

	close(q.newEvent)
	q.newEvent = nil
}

func (q *unlimitedEventQueue) Next(ctx context.Context) (Event, error) {
	for {
		q.lock.Lock()
		if len(q.events) > 0 {
			e := q.events[0]
			q.events = q.events[1:]
			q.lock.Unlock()
			return e, nil
		}

		ch := q.newEvent
		if ch == nil {
			q.lock.Unlock()
			return Event{}, ErrEventQueueClosed
		}
		q.lock.Unlock()

		select {
		case <-ctx.Done():
			return Event{}, ctx.Err()
		case <-ch:
			continue
		}
	}
}
