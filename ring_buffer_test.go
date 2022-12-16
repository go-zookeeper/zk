package zk

import (
	"testing"
)

func TestRingBuffer_Cap(t *testing.T) {
	rb := NewRingBuffer[int](10)

	if rb.Cap() != 10 {
		t.Fatalf("expected capacity 10, got %d", rb.Cap())
	}
}

func TestRingBuffer_Push(t *testing.T) {
	rb := NewRingBuffer[int](10)

	for i := 0; i < 10; i++ {
		rb.Push(i)
	}
	if rb.Len() != 10 {
		t.Fatalf("expected length 10, got %d", rb.Len())
	}
	if rb.Cap() != 10 {
		t.Fatalf("expected capacity 10, got %d", rb.Cap())
	}

	// Verify the contents of the buffer
	if !slicesEqual(rb.ToSlice(), []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}) {
		t.Fatalf("expected items {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, got %v", rb.ToSlice())
	}

	// Overwrite items in the buffer.
	for i := 0; i < 5; i++ {
		rb.Push(-i)
	}
	if rb.Len() != 10 {
		t.Fatalf("expected length 10, got %d", rb.Len())
	}
	if rb.Cap() != 10 {
		t.Fatalf("expected capacity 10, got %d", rb.Cap())
	}

	// Verify the contents of the buffer
	if !slicesEqual(rb.ToSlice(), []int{5, 6, 7, 8, 9, 0, -1, -2, -3, -4}) {
		t.Fatalf("expected items {5, 6, 7, 8, 0, 0, -1, -2, -3, -4}, got %v", rb.ToSlice())
	}
}

func TestRingBuffer_Offer(t *testing.T) {
	rb := NewRingBuffer[int](10)

	for i := 0; i < 10; i++ {
		if !rb.Offer(i) {
			t.Fatalf("expected offer to succeed")
		}
	}
	if rb.Len() != 10 {
		t.Fatalf("expected length 10, got %d", rb.Len())
	}
	if rb.Cap() != 10 {
		t.Fatalf("expected capacity 10, got %d", rb.Cap())
	}

	// Verify the contents of the buffer
	if !slicesEqual(rb.ToSlice(), []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}) {
		t.Fatalf("expected items {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, got %v", rb.ToSlice())
	}

	// Offer will refuse to overwrite items in a full buffer.
	if rb.Offer(11) {
		t.Fatalf("expected offer to fail")
	}
}

func TestRingBuffer_Pop(t *testing.T) {
	rb := NewRingBuffer[int](10)

	for i := 0; i < 10; i++ {
		rb.Push(i)
	}

	for i := 0; i < 10; i++ {
		item, ok := rb.Pop()
		if !ok {
			t.Fatalf("expected item %d, got none", i)
		}
		if item != i {
			t.Fatalf("expected item %d, got %d", i, item)
		}
	}

	// Verify that the buffer is empty
	if rb.Len() != 0 {
		t.Fatalf("expected length 0, got %d", rb.Len())
	}
	_, ok := rb.Pop()
	if ok {
		t.Fatalf("expected no item, got one")
	}
}

func TestRingBuffer_Peek(t *testing.T) {
	rb := NewRingBuffer[int](10)

	for i := 0; i < 10; i++ {
		rb.Push(i)
	}

	for i := 0; i < 10; i++ {
		item, ok := rb.Peek()
		if !ok {
			t.Fatalf("expected item %d, got none", i)
		}
		if item != i {
			t.Fatalf("expected item %d, got %d", i, item)
		}
		_, _ = rb.Pop()
	}

	// Verify that the buffer is empty
	if rb.Len() != 0 {
		t.Fatalf("expected length 0, got %d", rb.Len())
	}
	_, ok := rb.Peek()
	if ok {
		t.Fatalf("expected no item, got one")
	}
}

func TestRingBuffer_Clear(t *testing.T) {
	rb := NewRingBuffer[int](10)

	for i := 0; i < 10; i++ {
		rb.Push(i)
	}

	rb.Clear()
	if rb.Len() != 0 {
		t.Fatalf("expected length 0, got %d", rb.Len())
	}
}

func TestRingBuffer_EnsureCapacity(t *testing.T) {
	rb := NewRingBuffer[int](10)

	for i := 0; i < 15; i++ {
		rb.Push(i)
	}

	rb.EnsureCapacity(20)
	if rb.Len() != 10 {
		t.Fatalf("expected length 10, got %d", rb.Len())
	}
	if rb.Cap() != 20 {
		t.Fatalf("expected capacity 20, got %d", rb.Cap())
	}

	// Verify the contents of the buffer
	if !slicesEqual(rb.ToSlice(), []int{5, 6, 7, 8, 9, 10, 11, 12, 13, 14}) {
		t.Fatalf("expected items {5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, got %v", rb.ToSlice())
	}

	rb.EnsureCapacity(5) // should not change capacity
	if rb.Cap() != 20 {
		t.Fatalf("expected capacity 20, got %d", rb.Cap())
	}
}

func slicesEqual[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
