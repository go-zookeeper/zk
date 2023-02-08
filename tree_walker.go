package zk

import (
	"context"
	gopath "path"
	"sync"

	"golang.org/x/sync/errgroup"
)

// ChildrenFunc is a function that returns the children of a node.
type ChildrenFunc func(ctx context.Context, path string) ([]string, *Stat, error)

// VisitorFunc is a function that is called for each node visited.
type VisitorFunc func(path string, stat *Stat) error

// VisitorCtxFunc is like VisitorFunc, but it takes a context.
type VisitorCtxFunc func(ctx context.Context, path string, stat *Stat) error

// VisitEvent is the event that is sent to the channel returned by various walk functions.
// If Err is not nil, it indicates that an error occurred while walking the tree.
type VisitEvent struct {
	Path string
	Stat *Stat
	Err  error
}

// InitTreeWalker initializes a TreeWalker with the given fetcher function and root path.
func InitTreeWalker(fetcher ChildrenFunc, path string) TreeWalker {
	return TreeWalker{
		fetcher:     fetcher,
		path:        path,
		includeRoot: true,
		walker:      walkBreadthFirst,
		lifo:        false,
		decorator:   func(v VisitorCtxFunc) VisitorCtxFunc { return v }, // Identity.
		concurrency: 1,
	}
}

// TreeWalker provides flexible traversal of a tree of nodes rooted at a specific path.
// The traversal can be configured by calling one of DepthFirst, BreadthFirst.
// By default, the walker will visit the root node, but this can be changed by calling IncludeRoot.
// The walker can be configured to only visit leaf nodes by calling LeavesOnly.
// The concurrency level can be configured by calling Concurrency; the default is 1.
type TreeWalker struct {
	fetcher     ChildrenFunc         // Function that returns the children of a node.
	path        string               // The path to root node.
	includeRoot bool                 // Whether to include the root node in the traversal.
	walker      walkFunc             // The function that performs the walk steps of traversal.
	lifo        bool                 // Whether process traversal steps in LIFO order; only used by depth-first traversal.
	decorator   visitorDecoratorFunc // Decorates the visitor function.
	concurrency int                  // The number of workers to use for traversal; default is 1.
}

// DepthFirst configures the walker for a sequential traversal in depth-first order.
func (w TreeWalker) DepthFirst() TreeWalker {
	return TreeWalker{
		fetcher:     w.fetcher,
		path:        w.path,
		includeRoot: w.includeRoot,
		walker:      walkDepthFirst,
		lifo:        true,
		decorator:   w.decorator,
		concurrency: w.concurrency,
	}
}

// BreadthFirst configures the walker for a sequential traversal in breadth-first order.
func (w TreeWalker) BreadthFirst() TreeWalker {
	return TreeWalker{
		fetcher:     w.fetcher,
		path:        w.path,
		includeRoot: w.includeRoot,
		walker:      walkBreadthFirst,
		lifo:        false,
		decorator:   w.decorator,
		concurrency: w.concurrency,
	}
}

// IncludeRoot configures the walker to visit the root node or not.
func (w TreeWalker) IncludeRoot(included bool) TreeWalker {
	return TreeWalker{
		fetcher:     w.fetcher,
		path:        w.path,
		includeRoot: included,
		walker:      w.walker,
		lifo:        w.lifo,
		decorator:   w.decorator,
		concurrency: w.concurrency,
	}
}

// LeavesOnly configures the walker to only visit leaf nodes.
func (w TreeWalker) LeavesOnly() TreeWalker {
	return TreeWalker{
		fetcher:     w.fetcher,
		path:        w.path,
		includeRoot: w.includeRoot,
		walker:      w.walker,
		lifo:        w.lifo,
		decorator: func(v VisitorCtxFunc) VisitorCtxFunc {
			// Only call the original visitor if the node has no children.
			return func(ctx context.Context, path string, stat *Stat) error {
				if stat.NumChildren == 0 {
					return v(ctx, path, stat)
				}
				return nil
			}
		},
		concurrency: w.concurrency,
	}
}

// Concurrency configures the walker with the specified concurrency level.
func (w TreeWalker) Concurrency(concurrency int) TreeWalker {
	return TreeWalker{
		fetcher:     w.fetcher,
		path:        w.path,
		includeRoot: w.includeRoot,
		walker:      w.walker,
		lifo:        w.lifo,
		decorator:   w.decorator,
		concurrency: concurrency,
	}
}

// Walk begins traversing the tree and calls the visitor function for each node visited.
// Note: The DepthFirstParallel and BreadthFirstParallel traversals require the visitor function to be thread-safe.
func (w TreeWalker) Walk(visitor VisitorFunc) error {
	// Adapt VisitorFunc to VisitorCtxFunc.
	vc := func(ctx context.Context, path string, stat *Stat) error {
		return visitor(path, stat)
	}
	return w.WalkCtx(context.Background(), vc)
}

// WalkCtx is like Walk, but takes a context that can be used to cancel the walk.
func (w TreeWalker) WalkCtx(ctx context.Context, visitor VisitorCtxFunc) error {
	visitor = w.decorator(visitor)                  // Apply decorator.
	steps := newTraversalBuffer(w.lifo)             // Buffer for traversal steps.
	workers, workerCtx := errgroup.WithContext(ctx) // Tracks the workers and the context for the entire walk.

	go func() {
		// As soon as the worker context is cancelled, abort the buffer to unblock callers of consumeNext.
		<-workerCtx.Done()
		steps.abort() // No-op if already complete.
	}()

	// Start the workers, each of which will consume steps from buffer and execute them.
	for i := 0; i < w.concurrency; i++ {
		workers.Go(func() error {
			for {
				ok, err := steps.consumeNext(func(step traversalStep) error {
					if step.op == treeOpVisit {
						return visitor(workerCtx, step.path, step.stat)
					}
					return w.walker(workerCtx, w.fetcher, step, steps)
				})
				if err != nil {
					return err // Error occurred.
				}
				if !ok {
					return nil // Done.
				}
			}
		})
	}

	// Start the traversal: add the root path to step buffer.
	if w.includeRoot {
		steps.add(traversalStep{op: treeOpWalkIncludeSelf, path: w.path})
	} else {
		steps.add(traversalStep{op: treeOpWalkExcludeSelf, path: w.path})
	}

	// Wait for all workers to exit, or for an error to occur.
	return workers.Wait()
}

// WalkChan begins traversing the tree and sends the results to the returned channel.
// The channel will be buffered with the given size.
// The channel is closed when the traversal is complete.
// If an error occurs, an error event will be sent to the channel before it is closed.
func (w TreeWalker) WalkChan(bufferSize int) <-chan VisitEvent {
	return w.WalkChanCtx(context.Background(), bufferSize)
}

// WalkChanCtx is like WalkChan, but it takes a context that can be used to cancel the walk.
func (w TreeWalker) WalkChanCtx(ctx context.Context, bufferSize int) <-chan VisitEvent {
	ch := make(chan VisitEvent, bufferSize)
	visitor := func(ctx context.Context, path string, stat *Stat) error {
		ch <- VisitEvent{Path: path, Stat: stat}
		return nil
	}
	go func() {
		defer close(ch)
		if err := w.WalkCtx(ctx, visitor); err != nil {
			ch <- VisitEvent{Err: err}
		}
	}()
	return ch
}

// treeOp represent a type of operation to perform on a node during a tree traversal.
type treeOp int

const (
	// treeOpWalkIncludeSelf indicates that the node should be visited and its children should be traversed.
	treeOpWalkIncludeSelf treeOp = iota

	// treeOpWalkExcludeSelf indicates that the node should not be visited, but its children should be traversed.
	treeOpWalkExcludeSelf

	// treeOpVisit indicates that the node should be visited.
	treeOpVisit
)

// traverseStep describes a step in a tree traversal, including the path and the operation to perform.
type traversalStep struct {
	op   treeOp // The operation to perform.
	path string // The path to traverse.
	stat *Stat  // Only used for treeOpVisit.
}

type traversalStepAdder interface {
	add(step traversalStep)
}

func newTraversalBuffer(lifo bool) *traversalBuffer {
	q := &traversalBuffer{
		buf:     make([]traversalStep, 0),
		lifo:    lifo,
		pending: 0,
	}
	q.nonEmptyCond = sync.NewCond(&q.mu) // Signals when the buffer is non-empty.
	return q
}

type traversalBuffer struct {
	buf          []traversalStep // The buffer of steps to be consumed.
	lifo         bool            // True if the buffer should be treated as a LIFO; otherwise FIFO.
	pending      int32           // Number of pending steps. Set to -1 when traversal is complete.
	mu           sync.Mutex      // Protects all fields.
	nonEmptyCond *sync.Cond      // Signals when the buffer is non-empty.
}

func (tb *traversalBuffer) add(step traversalStep) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	if tb.pending < 0 { // Anything < 0 means traversal is complete.
		panic("traversalBuffer: add called after traversal was complete")
	}

	tb.pending++
	tb.buf = append(tb.buf, step)
	tb.nonEmptyCond.Signal()
}

func (tb *traversalBuffer) consumeNext(consumer func(step traversalStep) error) (bool, error) {
	tb.mu.Lock()

	// Wait until the buffer is non-empty, the context is canceled or traversal is complete.
	for {
		if tb.pending < 0 { // Anything < 0 means traversal is complete.
			tb.mu.Unlock()
			return false, nil // Nothing left to do.
		}
		if len(tb.buf) == 0 {
			// Wait for more steps to be added.
			// This must also be signalled if traversal is aborted or completed while waiting.
			tb.nonEmptyCond.Wait()
		} else {
			break
		}
	}

	var step traversalStep

	if tb.lifo {
		// Pop the last element.
		step = tb.buf[len(tb.buf)-1]
		tb.buf = tb.buf[:len(tb.buf)-1]
	} else {
		// Pop the first element.
		step = tb.buf[0]
		tb.buf = tb.buf[1:]
	}
	tb.mu.Unlock()

	// Call the consumer outside the lock.
	// This allows the consumer to add more steps to the queue.
	err := consumer(step)

	tb.mu.Lock()
	tb.pending--         // Note: This can go < 0 if traversal was aborted during consume, and that is perfectly fine.
	if tb.pending == 0 { // We just completed the last step!
		tb.pending = -1             // Set to -1 to indicate that traversal is complete.
		tb.nonEmptyCond.Broadcast() // Wake up all waiters.
	}
	tb.mu.Unlock()

	if err != nil {
		return false, err
	}

	return true, nil
}

func (tb *traversalBuffer) abort() {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	if tb.pending < 0 {
		return // Already complete.
	}

	tb.pending = -1 // Anything < 0 means traversal is complete.
	tb.buf = nil
	tb.nonEmptyCond.Broadcast()
}

// walkFunc is a function that implements a queue-based tree traversal.
// The fetcher function is used to fetch the children of a node.
// The current step describes the current node and the operation to perform.
// The adder function is used to add new traversal steps.
type walkFunc func(
	ctx context.Context,
	fetcher ChildrenFunc,
	current traversalStep,
	adder traversalStepAdder,
) error

// visitorDecoratorFunc is a function that decorates a visitor function.
type visitorDecoratorFunc func(v VisitorCtxFunc) VisitorCtxFunc

// walkDepthFirst walks the tree rooted at target path in depth-first order.
// The adder steps are assumed to be consumed in LIFO order.
func walkDepthFirst(
	ctx context.Context,
	fetcher ChildrenFunc,
	current traversalStep,
	stack traversalStepAdder,
) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	children, stat, err := fetcher(ctx, current.path)
	if err != nil {
		if err == ErrNoNode {
			return nil // Ignore ErrNoNode.
		}
		return err
	}

	if current.op == treeOpWalkIncludeSelf {
		stack.add(traversalStep{op: treeOpVisit, path: current.path, stat: stat})
	}

	// Add children in reverse order to account for LIFO processing order.
	// We desire children to be visited left-to-right order (as returned by fetcher).
	for i := len(children) - 1; i >= 0; i-- {
		stack.add(traversalStep{op: treeOpWalkIncludeSelf, path: gopath.Join(current.path, children[i])})
	}

	return nil
}

// walkBreadthFirst walks the tree rooted at target path in breadth-first order.
// The adder steps are assumed to be consumed in FIFO order.
func walkBreadthFirst(
	ctx context.Context,
	fetcher ChildrenFunc,
	current traversalStep,
	queue traversalStepAdder,
) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	children, stat, err := fetcher(ctx, current.path)
	if err != nil {
		if err == ErrNoNode {
			return nil // Ignore ErrNoNode.
		}
		return err
	}

	if current.op == treeOpWalkIncludeSelf {
		queue.add(traversalStep{op: treeOpVisit, path: current.path, stat: stat})
	}

	// Add children in order to account for FIFO processing order.
	// We desire children to be visited left-to-right order (as returned by fetcher).
	for _, child := range children {
		queue.add(traversalStep{op: treeOpWalkIncludeSelf, path: gopath.Join(current.path, child)})
	}

	return nil
}
