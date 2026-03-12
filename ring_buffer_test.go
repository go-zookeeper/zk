package zk

import (
	"slices"
	"testing"
)

func Test_ringBuffer_cap(t *testing.T) {
	rb := newRingBuffer[int](10)

	if rb.cap() != 10 {
		t.Fatalf("expected capacity 10, got %d", rb.cap())
	}
}

func Test_ringBuffer_push(t *testing.T) {
	rb := newRingBuffer[int](10)

	for i := range 10 {
		rb.push(i)
	}
	if rb.len() != 10 {
		t.Fatalf("expected length 10, got %d", rb.len())
	}
	if rb.cap() != 10 {
		t.Fatalf("expected capacity 10, got %d", rb.cap())
	}

	// Verify the contents of the buffer
	if !slices.Equal(rb.toSlice(), []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}) {
		t.Fatalf("expected items {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, got %v", rb.toSlice())
	}

	// Overwrite items in the buffer.
	for i := range 5 {
		rb.push(-i)
	}
	if rb.len() != 10 {
		t.Fatalf("expected length 10, got %d", rb.len())
	}
	if rb.cap() != 10 {
		t.Fatalf("expected capacity 10, got %d", rb.cap())
	}

	// Verify the contents of the buffer
	if !slices.Equal(rb.toSlice(), []int{5, 6, 7, 8, 9, 0, -1, -2, -3, -4}) {
		t.Fatalf("expected items {5, 6, 7, 8, 0, 0, -1, -2, -3, -4}, got %v", rb.toSlice())
	}
}

func Test_ringBuffer_offer(t *testing.T) {
	rb := newRingBuffer[int](10)

	for i := range 10 {
		if !rb.offer(i) {
			t.Fatalf("expected offer to succeed")
		}
	}
	if rb.len() != 10 {
		t.Fatalf("expected length 10, got %d", rb.len())
	}
	if rb.cap() != 10 {
		t.Fatalf("expected capacity 10, got %d", rb.cap())
	}

	// Verify the contents of the buffer
	if !slices.Equal(rb.toSlice(), []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}) {
		t.Fatalf("expected items {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, got %v", rb.toSlice())
	}

	// offer will refuse to overwrite items in a full buffer.
	if rb.offer(11) {
		t.Fatalf("expected offer to fail")
	}
}

func Test_ringBuffer_pop(t *testing.T) {
	rb := newRingBuffer[int](10)

	for i := range 10 {
		rb.push(i)
	}

	for i := range 10 {
		item, ok := rb.pop()
		if !ok {
			t.Fatalf("expected item %d, got none", i)
		}
		if item != i {
			t.Fatalf("expected item %d, got %d", i, item)
		}
	}

	// Verify that the buffer is empty
	if rb.len() != 0 {
		t.Fatalf("expected length 0, got %d", rb.len())
	}
	_, ok := rb.pop()
	if ok {
		t.Fatalf("expected no item, got one")
	}
}

func Test_ringBuffer_peek(t *testing.T) {
	rb := newRingBuffer[int](10)

	for i := range 10 {
		rb.push(i)
	}

	for i := range 10 {
		item, ok := rb.peek()
		if !ok {
			t.Fatalf("expected item %d, got none", i)
		}
		if item != i {
			t.Fatalf("expected item %d, got %d", i, item)
		}
		_, _ = rb.pop()
	}

	// Verify that the buffer is empty
	if rb.len() != 0 {
		t.Fatalf("expected length 0, got %d", rb.len())
	}
	_, ok := rb.peek()
	if ok {
		t.Fatalf("expected no item, got one")
	}
}

func Test_ringBuffer_clear(t *testing.T) {
	rb := newRingBuffer[int](10)

	for i := range 10 {
		rb.push(i)
	}

	rb.clear()
	if rb.len() != 0 {
		t.Fatalf("expected length 0, got %d", rb.len())
	}
}

func Test_ringBuffer_ensureCapacity(t *testing.T) {
	rb := newRingBuffer[int](10)

	for i := range 15 {
		rb.push(i)
	}

	rb.ensureCapacity(20)
	if rb.len() != 10 {
		t.Fatalf("expected length 10, got %d", rb.len())
	}
	if rb.cap() != 20 {
		t.Fatalf("expected capacity 20, got %d", rb.cap())
	}

	// Verify the contents of the buffer
	if !slices.Equal(rb.toSlice(), []int{5, 6, 7, 8, 9, 10, 11, 12, 13, 14}) {
		t.Fatalf("expected items {5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, got %v", rb.toSlice())
	}

	rb.ensureCapacity(5) // should not change capacity
	if rb.cap() != 20 {
		t.Fatalf("expected capacity 20, got %d", rb.cap())
	}
}
