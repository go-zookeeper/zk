package zk

import (
	"context"
	"errors"
	"fmt"
	"iter"
	gopath "path"
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

type TraversalOrder int

const (
	// BreadthFirstOrder indicates that the tree should be traversed in breadth-first order.
	BreadthFirstOrder TraversalOrder = iota
	// DepthFirstOrder indicates that the tree should be traversed in depth-first order.
	DepthFirstOrder
)

// NewTreeWalker creates a new TreeWalker with the given fetcher function and root path.
func NewTreeWalker(fetcher ChildrenFunc, path string, order TraversalOrder) *TreeWalker {
	return &TreeWalker{
		fetcher: fetcher,
		path:    path,
		order:   order,
	}
}

// TreeWalker provides traversal of a tree of nodes rooted at a specific path.
type TreeWalker struct {
	fetcher ChildrenFunc
	path    string
	order   TraversalOrder
}

// Walk begins traversing the tree and calls the visitor function for each node visited.
func (w *TreeWalker) Walk(visitor VisitorFunc) error {
	// Adapt VisitorFunc to VisitorCtxFunc.
	vc := func(ctx context.Context, path string, stat *Stat) error {
		return visitor(path, stat)
	}
	return w.WalkCtx(context.Background(), vc)
}

// WalkCtx is like Walk, but takes a context that can be used to cancel the walk.
func (w *TreeWalker) WalkCtx(ctx context.Context, visitor VisitorCtxFunc) error {
	switch w.order {
	case BreadthFirstOrder:
		return w.walkBreadthFirst(ctx, w.path, visitor)
	case DepthFirstOrder:
		return w.walkDepthFirst(ctx, w.path, visitor)
	default:
		return fmt.Errorf("unknown traversal order: %d", w.order)
	}
}

// WalkChan begins traversing the tree and sends the results to the returned channel.
// The channel will be buffered with the given size.
// The channel is closed when the traversal is complete.
// If an error occurs, an error event will be sent to the channel before it is closed.
func (w *TreeWalker) WalkChan(bufferSize int) <-chan VisitEvent {
	return w.WalkChanCtx(context.Background(), bufferSize)
}

// WalkChanCtx is like WalkChan, but it takes a context that can be used to cancel the walk.
func (w *TreeWalker) WalkChanCtx(ctx context.Context, bufferSize int) <-chan VisitEvent {
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

// All returns an iterator over all nodes in the tree.
// It uses context.Background internally.
func (w *TreeWalker) All() iter.Seq2[string, *Stat] {
	return w.AllCtx(context.Background())
}

// AllCtx returns an iterator over all nodes in the tree.
// The caller can stop iteration early by breaking out of the range loop.
func (w *TreeWalker) AllCtx(ctx context.Context) iter.Seq2[string, *Stat] {
	return func(yield func(string, *Stat) bool) {
		err := w.WalkCtx(ctx, func(_ context.Context, path string, stat *Stat) error {
			if !yield(path, stat) {
				return errBreak
			}
			return nil
		})
		_ = err // errBreak is expected when the caller breaks out of the range loop.
	}
}

var errBreak = errors.New("break")

// walkBreadthFirst walks the tree rooted at path in breadth-first order.
func (w *TreeWalker) walkBreadthFirst(ctx context.Context, path string, visitor VisitorCtxFunc) error {
	children, stat, err := w.fetcher(ctx, path)
	if err != nil {
		if errors.Is(err, ErrNoNode) {
			return nil // Ignore ErrNoNode.
		}
		return err
	}

	if err = visitor(ctx, path, stat); err != nil {
		return err
	}

	for _, child := range children {
		childPath := gopath.Join(path, child)
		if err = w.walkBreadthFirst(ctx, childPath, visitor); err != nil {
			return err
		}
	}

	return nil
}

// walkDepthFirst walks the tree rooted at path in depth-first order.
func (w *TreeWalker) walkDepthFirst(ctx context.Context, path string, visitor VisitorCtxFunc) error {
	children, stat, err := w.fetcher(ctx, path)
	if err != nil {
		if errors.Is(err, ErrNoNode) {
			return nil // Ignore ErrNoNode.
		}
		return err
	}

	for _, child := range children {
		childPath := gopath.Join(path, child)
		if err = w.walkDepthFirst(ctx, childPath, visitor); err != nil {
			return err
		}
	}

	if err = visitor(ctx, path, stat); err != nil {
		return err
	}

	return nil
}
