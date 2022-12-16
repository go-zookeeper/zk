package zk

import "fmt"

// RingBuffer is a circular buffer that overwrites the oldest item when full.
// It is not thread-safe.
type RingBuffer[T any] struct {
	// The buffer.
	buf []T
	// The index of the first item in the buffer.
	head int
	// The index of the last item in the buffer.
	tail int
	// The number of items in the buffer.
	count int
	// The capacity of the buffer.
	capacity int
}

// NewRingBuffer creates a new RingBuffer with the given capacity.
func NewRingBuffer[T any](capacity int) *RingBuffer[T] {
	return &RingBuffer[T]{
		buf:      make([]T, capacity),
		capacity: capacity,
	}
}

func (rb *RingBuffer[T]) IsEmpty() bool {
	return rb.count == 0
}

// Len returns the number of items in the buffer.
func (rb *RingBuffer[T]) Len() int {
	return rb.count
}

// Cap returns the capacity of the buffer.
func (rb *RingBuffer[T]) Cap() int {
	return rb.capacity
}

// Offer adds an item to the buffer, if there is space.
// Returns true if the item was added, false otherwise (buffer full).
func (rb *RingBuffer[T]) Offer(t T) bool {
	if rb.count == rb.capacity {
		return false
	}
	rb.buf[rb.tail] = t
	rb.tail = (rb.tail + 1) % rb.capacity
	rb.count++
	return true
}

// Push adds an item to the buffer.
// If the buffer is full, the oldest item is overwritten.
func (rb *RingBuffer[T]) Push(t T) {
	rb.buf[rb.tail] = t
	rb.tail = (rb.tail + 1) % rb.capacity
	if rb.count == rb.capacity {
		rb.head = rb.tail
	} else {
		rb.count++
	}
}

// Peek returns the oldest item in the buffer, without removing it.
// If the buffer is empty, returns the zero value and false.
func (rb *RingBuffer[T]) Peek() (T, bool) {
	if rb.count == 0 {
		var zero T
		return zero, false
	}
	return rb.buf[rb.head], true
}

// Pop returns the oldest item in the buffer, removing it.
// If the buffer is empty, returns the zero value and false.
func (rb *RingBuffer[T]) Pop() (T, bool) {
	if rb.count == 0 {
		var zero T
		return zero, false
	}
	t := rb.buf[rb.head]
	rb.head = (rb.head + 1) % rb.capacity
	rb.count--
	return t, true
}

// Clear removes all items from the buffer.
func (rb *RingBuffer[T]) Clear() {
	rb.head = 0
	rb.tail = 0
	rb.count = 0
}

// EnsureCapacity increases the capacity of the buffer to at least the given capacity.
// If the buffer is already at least that large, this is a no-op.
func (rb *RingBuffer[T]) EnsureCapacity(minCapacity int) {
	if minCapacity <= rb.capacity {
		return
	}
	newBuf := make([]T, minCapacity)
	if rb.count > 0 {
		if rb.head < rb.tail {
			copy(newBuf, rb.buf[rb.head:rb.tail])
		} else {
			n := copy(newBuf, rb.buf[rb.head:])
			copy(newBuf[n:], rb.buf[:rb.tail])
		}
	}
	rb.buf = newBuf
	rb.head = 0
	rb.tail = rb.count
	rb.capacity = minCapacity
}

// ToSlice returns a slice of the items in the buffer (not aliased).
func (rb *RingBuffer[T]) ToSlice() []T {
	if rb.count == 0 {
		return []T{}
	}
	out := make([]T, rb.count)
	if rb.tail > rb.head {
		copy(out, rb.buf[rb.head:rb.tail])
	} else {
		copy(out, rb.buf[rb.head:])
		copy(out[rb.capacity-rb.head:], rb.buf[:rb.tail])
	}
	return out
}

func (rb *RingBuffer[T]) String() string {
	return fmt.Sprintf("RingBuffer[%d/%d]", rb.count, rb.capacity)
}
