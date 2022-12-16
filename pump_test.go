package zk

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestPump_NoConsumerLag(t *testing.T) {
	var stalled atomic.Bool
	stallCallback := func() {
		t.Log("pump has stalled")
		stalled.Store(true)
	}

	p := NewPump[int](stallCallback)
	defer p.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start receiving items from pump in a new goroutine.
	// We block for 1 ms every 256 items received and for 10 ms every 1024 items received.
	consumerErr := make(chan error, 1)
	go func() {
		startTime := time.Now()
		defer close(consumerErr)

		for i := 0; i < 65536; i++ {
			item, ok := p.Take(ctx)
			if !ok {
				if ctx.Err() != nil {
					consumerErr <- ctx.Err()
				} else {
					consumerErr <- errors.New("expected to receive an item, but take returned false")
				}
				break
			}
			if item != i {
				consumerErr <- fmt.Errorf("expected to receive item %d, but got %d", i, item)
				break
			}
		}
		t.Logf("consumer took %v to receive all items", time.Since(startTime))
	}()

	// Send items to the pump in this goroutine.
	// This will give items as fast as possible without pausing.
	startTime := time.Now()
	for i := 0; i < 65536; i++ {
		ok := p.Give(ctx, i)
		if !ok {
			t.Fatalf("expected pump to be accept item: %d", i)
		}
	}
	t.Logf("producer took %v to send all items", time.Since(startTime))

	p.CloseInput()
	err := p.WaitUntilStopped(ctx)
	if err != nil {
		t.Fatalf("expected pump to stop cleanly, but saw error: %v", err)
	}

	if stalled.Load() {
		t.Fatalf("expected pump to not stall")
	}

	select {
	case err, ok := <-consumerErr:
		if ok {
			t.Fatalf("expected consumer to not see error, but saw: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for consumer to finish")
	}

	stats := p.Stats()
	if stats.intakeTotal != 65536 {
		t.Fatalf("expected stats.intakeTotal to be 32768, but was %d", stats.intakeTotal)
	}
	if stats.dischargeTotal != 65536 {
		t.Fatalf("expected stats.dischargeTotal to be 32768, but was %d", stats.dischargeTotal)
	}

	t.Logf("Peek reservoir size: %d", stats.reservoirPeek)
}

func TestPump_LowConsumerLag(t *testing.T) {
	var stalled atomic.Bool
	stallCallback := func() {
		t.Log("pump has stalled")
		stalled.Store(true)
	}

	p := NewPump[int](stallCallback)
	defer p.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start receiving items from pump in a new goroutine.
	// We block for 1 ms every 256 items received and for 10 ms every 1024 items received.
	consumerErr := make(chan error, 1)
	go func() {
		startTime := time.Now()
		defer close(consumerErr)

		for i := 0; i < 65536; i++ {
			item, ok := p.Take(ctx)
			if !ok {
				if ctx.Err() != nil {
					consumerErr <- ctx.Err()
				} else {
					consumerErr <- errors.New("expected to receive an item, but take returned false")
				}
				break
			}
			if item != i {
				consumerErr <- fmt.Errorf("expected to receive item %d, but got %d", i, item)
				break
			}
			// Block for 1 ms every 128 items received.
			if i%128 == 0 {
				time.Sleep(1 * time.Millisecond)
			}
		}
		t.Logf("consumer took %v to receive all items", time.Since(startTime))
	}()

	// Send items to the pump in this goroutine.
	// This will give items as fast as possible without pausing.
	startTime := time.Now()
	for i := 0; i < 65536; i++ {
		ok := p.Give(ctx, i)
		if !ok {
			t.Fatalf("expected pump to be accept item: %d", i)
		}
	}
	t.Logf("producer took %v to send all items", time.Since(startTime))

	p.CloseInput()
	err := p.WaitUntilStopped(ctx)
	if err != nil {
		t.Fatalf("expected pump to stop cleanly, but saw error: %v", err)
	}

	if stalled.Load() {
		t.Fatalf("expected pump to not stall")
	}

	select {
	case err, ok := <-consumerErr:
		if ok {
			t.Fatalf("expected consumer to not see error, but saw: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for consumer to finish")
	}

	stats := p.Stats()
	if stats.intakeTotal != 65536 {
		t.Fatalf("expected stats.intakeTotal to be 32768, but was %d", stats.intakeTotal)
	}
	if stats.dischargeTotal != 65536 {
		t.Fatalf("expected stats.dischargeTotal to be 32768, but was %d", stats.dischargeTotal)
	}

	t.Logf("Peek reservoir size: %d", stats.reservoirPeek)
}

func TestPump_HighConsumerLag(t *testing.T) {
	var stalled atomic.Bool
	stallCallback := func() {
		t.Log("pump has stalled")
		stalled.Store(true)
	}

	p := NewPump[int](stallCallback)
	defer p.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start receiving items from pump in a new goroutine.
	// We block for 1 ms every 256 items received and for 10 ms every 1024 items received.
	consumerErr := make(chan error, 1)
	go func() {
		startTime := time.Now()
		defer close(consumerErr)

		for i := 0; i < 65536; i++ {
			item, ok := p.Take(ctx)
			if !ok {
				if ctx.Err() != nil {
					consumerErr <- ctx.Err()
				} else {
					consumerErr <- errors.New("expected to receive an item, but take returned false")
				}
				break
			}
			if item != i {
				consumerErr <- fmt.Errorf("expected to receive item %d, but got %d", i, item)
				break
			}
			if i%2048 == 0 {
				time.Sleep(100 * time.Millisecond)
			}
		}
		t.Logf("consumer took %v to receive all items", time.Since(startTime))
	}()

	// Send items to the pump in this goroutine.
	// This will give items as fast as possible without pausing.
	startTime := time.Now()
	for i := 0; i < 65536; i++ {
		ok := p.Give(ctx, i)
		if !ok {
			t.Fatalf("expected pump to be accept item: %d", i)
		}
	}
	t.Logf("producer took %v to send all items", time.Since(startTime))

	p.CloseInput()
	err := p.WaitUntilStopped(ctx)
	if err != nil {
		t.Fatalf("expected pump to stop cleanly, but saw error: %v", err)
	}

	if stalled.Load() {
		t.Fatalf("expected pump to not stall")
	}

	select {
	case err, ok := <-consumerErr:
		if ok {
			t.Fatalf("expected consumer to not see error, but saw: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for consumer to finish")
	}

	stats := p.Stats()
	if stats.intakeTotal != 65536 {
		t.Fatalf("expected stats.intakeTotal to be 32768, but was %d", stats.intakeTotal)
	}
	if stats.dischargeTotal != 65536 {
		t.Fatalf("expected stats.dischargeTotal to be 32768, but was %d", stats.dischargeTotal)
	}

	t.Logf("Peek reservoir size: %d", stats.reservoirPeek)
}

func TestPump_Stall(t *testing.T) {
	var stalled atomic.Bool
	stallCallback := func() {
		t.Log("pump has stalled")
		stalled.Store(true)
	}

	p := NewPump[int](stallCallback)
	defer p.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Send items to the pump in this goroutine.
	// This will give items as fast as possible without pausing.
	for i := 0; i < 65536; i++ {
		ok := p.Give(ctx, i)
		if !ok {
			break // Expected to fail when pump is stalled.
		}
	}

	// No consumer to receive items, so pump should stall and stop naturally.
	err := p.WaitUntilStopped(ctx)
	if err != nil {
		t.Fatalf("expected pump to stop cleanly, but saw error: %v", err)
	}

	if !stalled.Load() {
		t.Fatalf("expected pump to stall")
	}

	stats := p.Stats()
	t.Logf("Peek reservoir size: %d", stats.reservoirPeek)

	// We should see the output channel closed.
	for {
		select {
		case _, ok := <-p.OutChan():
			if !ok {
				return // Saw end of channel.
			}
		case <-ctx.Done():
			t.Fatalf("timed out waiting for consumer to finish")
		}
	}
}

func TestPump_Offer_Accepted(t *testing.T) {
	p := NewPump[int](nil)
	defer p.Stop()

	ok := p.Offer(1)
	if !ok {
		t.Fatalf("expected pump to accept item")
	}
}

func TestPump_Offer_RejectedAfterInputClosed(t *testing.T) {
	p := NewPump[int](nil)
	defer p.Stop()

	p.CloseInput()

	ok := p.Offer(1)
	if ok {
		t.Fatalf("expected pump to not accept item after input is closed")
	}
}

func TestPump_Offer_RejectedAfterStopped(t *testing.T) {
	p := NewPump[int](nil)
	p.Stop()

	ok := p.Offer(1)
	if ok {
		t.Fatalf("expected pump to not accept item after stopped")
	}
}

func TestPump_Give_Accepted(t *testing.T) {
	p := NewPump[int](nil)
	defer p.Stop()

	ok := p.Give(context.Background(), 1)
	if !ok {
		t.Fatalf("expected pump to accept item")
	}
}

func TestPump_Give_RejectedAfterInputClosed(t *testing.T) {
	p := NewPump[int](nil)
	defer p.Stop()

	p.CloseInput()

	ok := p.Give(context.Background(), 1)
	if ok {
		t.Fatalf("expected pump to not accept item after input is closed")
	}
}

func TestPump_Give_RejectedAfterStopped(t *testing.T) {
	p := NewPump[int](nil)
	p.Stop()

	ok := p.Give(context.Background(), 1)
	if ok {
		t.Fatalf("expected pump to not accept item after stopped")
	}
}

func TestPump_Poll_Accepted(t *testing.T) {
	p := NewPump[int](nil)
	defer p.Stop()

	_ = p.Give(context.Background(), 1)
	time.Sleep(100 * time.Millisecond)

	item, ok := p.Poll()
	if !ok {
		t.Fatalf("expected pump to receive item")
	}
	if item != 1 {
		t.Fatalf("expected pump to receive item 1, but got %d", item)
	}
}

func TestPump_Poll_RejectedAfterStopped(t *testing.T) {
	p := NewPump[int](nil)
	p.Stop()

	_, ok := p.Poll()
	if ok {
		t.Fatalf("expected pump to not receive item,")
	}
}

func TestPump_Take_Accepted(t *testing.T) {
	p := NewPump[int](nil)
	defer p.Stop()

	_ = p.Give(context.Background(), 1)

	item, ok := p.Take(context.Background())
	if !ok {
		t.Fatalf("expected pump to receive item")
	}
	if item != 1 {
		t.Fatalf("expected pump to receive item 1, but got %d", item)
	}
}
