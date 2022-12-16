package zk

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// The maximum size of reservoir before the pump stalls.
	pumpReservoirLimit = 2048
	// The reservoir size after which the pump will begin blocking sends to output.
	pumpReservoirBlockThreshold = int(pumpReservoirLimit * 0.75)
)

const (
	pumpConditionInputClosed = pumpCondition(iota)
	pumpConditionInputEmpty
	pumpConditionReservoirFull
	pumpConditionReservoirEmpty
	pumpConditionOutputFull
	pumpConditionStopRequested
)

type pumpCondition int

var pumpConditionNames = map[pumpCondition]string{
	pumpConditionInputClosed:    "InputClosed",
	pumpConditionInputEmpty:     "InputEmpty",
	pumpConditionReservoirFull:  "ReservoirFull",
	pumpConditionReservoirEmpty: "ReservoirEmpty",
	pumpConditionOutputFull:     "OutputFull",
	pumpConditionStopRequested:  "StopRequested",
}

func (c pumpCondition) String() string {
	if name := pumpConditionNames[c]; name != "" {
		return name
	}
	return "Unknown"
}

func NewPump[T any](stallCallback func()) *Pump[T] {
	cb := &Pump[T]{
		input:         make(chan T, 32),
		output:        make(chan T, 32),
		reservoir:     NewRingBuffer[T](32),
		started:       make(chan struct{}),
		stopRequested: make(chan struct{}),
		stopped:       make(chan struct{}),
		stallCallback: stallCallback,
	}

	go cb.run()
	<-cb.started // Wait for pump to start.

	return cb
}

type Pump[T any] struct {
	input          chan T         // Fixed-size input channel for producers.
	output         chan T         // Fixed-size output channel for consumers.
	reservoir      *RingBuffer[T] // Growable buffer to deal with input surge and/or output backpressure.
	started        chan struct{}  // Closed when the pump has started running.
	stopRequested  chan struct{}  // Closed when Stop has been called.
	stopped        chan struct{}  // Closed after pump has stopped running.
	stopOnce       sync.Once      // Ensures stopRequested is closed only once.
	closeInputOnce sync.Once      // Ensures input is closed only once.
	stallCallback  func()         // An optional callback to invoke when the pump stalls.
	intakeTotal    atomic.Int64   // Total number of values received from input.
	dischargeTotal atomic.Int64   // Total number of values sent to output.
	reservoirPeak  atomic.Int32   // Maximum size of reservoir.
}

type PumpStats struct {
	intakeTotal    int64
	dischargeTotal int64
	reservoirPeek  int32
}

// Stats returns the pump's statistics.
func (p *Pump[T]) Stats() PumpStats {
	return PumpStats{
		intakeTotal:    p.intakeTotal.Load(),
		dischargeTotal: p.dischargeTotal.Load(),
		reservoirPeek:  p.reservoirPeak.Load(),
	}
}

// OutChan returns the raw output channel for the pump.
func (p *Pump[T]) OutChan() <-chan T {
	return p.output
}

// Offer makes a non-blocking attempt to send the given value to the pump's input buffer.
// Returns true if the value was accepted; false otherwise.
// The value will not be accepted if the input buffer is full, the pump's input is closed or if the pump is stopped.
func (p *Pump[T]) Offer(t T) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			// Gracefully handle the case where input was closed.
			// Pump stall will cause premature closure of input channel which races with producer.
			ok = false
		}
	}()

	if p.IsStopRequested() {
		return false
	}

	select {
	case p.input <- t:
		ok = true
	case <-p.stopRequested:
	default:
	}

	return
}

// Give makes a blocking attempt to send the given value to the pump's input buffer.
// Returns true if the value was accepted; false otherwise.
// The value will be rejected if the pump's input is closed, if the pump is stopped, or if the context is canceled.
// If the pump's input buffer is full, this method will block until the value is accepted or rejected.
func (p *Pump[T]) Give(ctx context.Context, t T) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			// Gracefully handle the case where input was closed.
			// Pump stall will cause premature closure of input channel which races with producer.
			ok = false
		}
	}()

	if p.IsStopRequested() {
		return false
	}

	select {
	case p.input <- t:
		ok = true
	case <-p.stopRequested:
	case <-ctx.Done():
	}

	return
}

// Poll makes a non-blocking attempt to receive a value from the pump's output buffer.
// Returns the value and true if a value was received; otherwise returns the zero value and false.
// The attempt to receive fails if the output buffer is empty or if the pump is stopped.
func (p *Pump[T]) Poll() (T, bool) {
	var zero T

	select {
	case t, ok := <-p.output:
		if ok {
			return t, true
		}
	case <-p.stopRequested:
	default:
	}

	return zero, false
}

// Take makes a blocking attempt to receive a value from the pump's output buffer.
// Returns the value and true if a value was received; otherwise returns the zero value and false.
// The attempt to receive fails if the pump is stopped or if the context is canceled.
// If the pump's output buffer is empty, this method will block until the value is received or the attempt fails.
func (p *Pump[T]) Take(ctx context.Context) (T, bool) {
	var zero T

	select {
	case t, ok := <-p.output:
		if ok {
			return t, true
		}
	case <-p.stopRequested:
	case <-ctx.Done():
	}

	return zero, false
}

// CloseInput prevents any further values from being accepted into the pump's input buffer and allows the pump to drain.
// After all previously received values have been drained to the output buffer, the pump will stop naturally.
// This method is idempotent and safe to call multiple times.
func (p *Pump[T]) CloseInput() {
	p.closeInputOnce.Do(func() {
		close(p.input)
	})
}

// Stop immediately halts the pump and discards any values that have not yet been drained to the output buffer.
// It is preferable to call CloseInput instead, which allows the pump to drain naturally.
// This method is idempotent and safe to call multiple times.
func (p *Pump[T]) Stop() {
	p.stopOnce.Do(func() {
		close(p.stopRequested)
	})
}

// IsStopRequested returns true if the pump has been requested to stop; false otherwise.
func (p *Pump[T]) IsStopRequested() bool {
	select {
	case <-p.stopRequested:
		return true
	default:
		return false
	}
}

// WaitUntilStopped blocks until the pump has stopped.
// If the given context is canceled, this method returns immediately with an error.
func (p *Pump[T]) WaitUntilStopped(ctx context.Context) error {
	select {
	case <-p.stopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// run is the main pump loop.
func (p *Pump[T]) run() {
	defer close(p.stopped) // On exit, signal that that pump has stopped.
	defer close(p.output)  // On exit, close the output buffer.

	tm := time.NewTimer(0) // Reusable timer for blocking ops.
	defer tm.Stop()

	close(p.started) // Signal that we have started.

	endOfInput := false
	for !endOfInput {
		if p.reservoir.IsEmpty() {
			// The reservoir is empty, so try to fill the output directly from the input.
			intakeCount, dischargeCount, cond := p.transferDirect(tm)
			p.intakeTotal.Add(intakeCount)
			p.dischargeTotal.Add(dischargeCount)
			switch cond {
			case pumpConditionInputClosed:
				endOfInput = true
				continue
			case pumpConditionStopRequested:
				return
			}
		}

		// The reservoir is not empty.
		// Intake and discharge at the same time (blocking on both).
		intakeCount, dischargeCount, cond := p.intakeAndDischarge(tm)
		p.intakeTotal.Add(intakeCount)
		p.dischargeTotal.Add(dischargeCount)
		switch cond {
		case pumpConditionInputClosed:
			endOfInput = true
			continue
		case pumpConditionStopRequested:
			return
		case pumpConditionReservoirEmpty:
			continue // We can try a direct transfer once again.
		case pumpConditionReservoirFull:
			// The output is full and the reservoir limit has been reached. This is fatal!
			p.Stop()
			if p.stallCallback != nil {
				p.stallCallback()
			}
			return
		}
	}

	// The input is dry, so drain what remains from the reservoir.
	if !p.reservoir.IsEmpty() {
		count, _ := p.discharge()
		p.dischargeTotal.Add(count)
	}
}

// transferDirect drains the input directly into the output.
// Returns when the input is closed, the pump is stopped, or the output is full.
func (p *Pump[T]) transferDirect(tm *time.Timer) (int64, int64, pumpCondition) {
	var intakeCount, dischargeCount int64

	for {
		var t T
		var ok bool

		select {
		case t, ok = <-p.input:
			if !ok {
				return intakeCount, dischargeCount, pumpConditionInputClosed
			}
			intakeCount++
		case <-p.stopRequested:
			return intakeCount, dischargeCount, pumpConditionStopRequested
		}

		// Try non-blocking send to output.
		select {
		case p.output <- t:
			dischargeCount++
			continue
		default:
		}

		safeResetTimer(tm, time.Millisecond)

		// Try (time-limited) blocking send to output.
		select {
		case p.output <- t:
			dischargeCount++
		case <-p.stopRequested:
			return intakeCount, dischargeCount, pumpConditionStopRequested
		case <-tm.C:
			// Output still full, so we begin filling the reservoir.
			p.pushReservoir(t)
			return intakeCount, dischargeCount, pumpConditionOutputFull
		}
	}
}

// intakeAndDischarge concurrently drains the input into reservoir and fills the output from reservoir.
// Returns when the input is closed, the pump is stopped, or the reservoir limit has been reached.
func (p *Pump[T]) intakeAndDischarge(tm *time.Timer) (int64, int64, pumpCondition) {
	var intakeCount, dischargeCount int64

	for {
		rlen := p.reservoir.Len()
		if rlen > pumpReservoirLimit { // No hope of draining the reservoir fast enough.
			return intakeCount, dischargeCount, pumpConditionReservoirFull
		}

		out, outOK := p.reservoir.Peek()
		if !outOK {
			return intakeCount, dischargeCount, pumpConditionReservoirEmpty
		}

		if rlen == p.reservoir.Cap() || rlen >= pumpReservoirBlockThreshold {
			// Reservoir needs to grow, or has reached threshold for blocking discharge.
			safeResetTimer(tm, time.Millisecond)
			// Try a (time-limited) blocking send to output before intaking more.
			// This will give the consumer a chance to catch up.
			select {
			case p.output <- out:
				_, _ = p.reservoir.Pop()
				dischargeCount++
				continue
			case <-p.stopRequested:
				return intakeCount, dischargeCount, pumpConditionStopRequested
			case <-tm.C:
				// Output is still full. Continue intaking and discharging.
			}
		}

		select {
		case p.output <- out:
			_, _ = p.reservoir.Pop()
			dischargeCount++
		case in, inOK := <-p.input:
			if !inOK {
				return intakeCount, dischargeCount, pumpConditionInputClosed
			}
			p.pushReservoir(in)
			intakeCount++
		case <-p.stopRequested:
			return intakeCount, dischargeCount, pumpConditionStopRequested
		}
	}
}

// discharge drains the reservoir into the output.
// Returns when the pump is stopped or the reservoir is empty.
func (p *Pump[T]) discharge() (int64, pumpCondition) {
	var count int64

	for {
		t, ok := p.reservoir.Pop()
		if !ok {
			return count, pumpConditionReservoirEmpty
		}

		select {
		case p.output <- t:
			count++
		case <-p.stopRequested:
			return count, pumpConditionStopRequested
		}
	}
}

// pushReservoir forces the given item into the reservoir; increases its capacity if necessary.
func (p *Pump[T]) pushReservoir(t T) {
	if !p.reservoir.Offer(t) {
		// We need to grow the reservoir.
		p.reservoir.EnsureCapacity(p.reservoir.Cap() * 2)
		_ = p.reservoir.Offer(t)
	}

	// Keep track of the peak reservoir size.
	l := int32(p.reservoir.Len())
	if l > p.reservoirPeak.Load() {
		p.reservoirPeak.Store(l)
	}
}

func safeResetTimer(tm *time.Timer, d time.Duration) {
	if !tm.Stop() {
		select {
		case <-tm.C:
		default:
		}
	}
	tm.Reset(d)
}
