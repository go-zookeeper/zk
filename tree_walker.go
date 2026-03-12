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
type VisitorFunc func(ctx context.Context, path string, stat *Stat) error

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

// All returns an iterator over all nodes in the tree and an error function.
// The caller can stop iteration early by breaking out of the range loop.
// After iteration, call the returned error function to check if the walk
// was interrupted by an error (as opposed to completing or being broken out of).
func (w *TreeWalker) All(ctx context.Context) (iter.Seq2[string, *Stat], func() error) {
	var walkErr error
	seq := func(yield func(string, *Stat) bool) {
		walkErr = w.Walk(ctx, func(_ context.Context, path string, stat *Stat) error {
			if !yield(path, stat) {
				return errBreak
			}
			return nil
		})
		if errors.Is(walkErr, errBreak) {
			walkErr = nil // Break is not an error.
		}
	}
	return seq, func() error { return walkErr }
}

var errBreak = errors.New("break")

// Walk traverses the tree and calls the visitor function for each node visited.
func (w *TreeWalker) Walk(ctx context.Context, visitor VisitorFunc) error {
	switch w.order {
	case BreadthFirstOrder:
		return w.walkBreadthFirst(ctx, w.path, visitor)
	case DepthFirstOrder:
		return w.walkDepthFirst(ctx, w.path, visitor)
	default:
		return fmt.Errorf("unknown traversal order: %d", w.order)
	}
}

// walkBreadthFirst walks the tree rooted at path in breadth-first order.
func (w *TreeWalker) walkBreadthFirst(ctx context.Context, path string, visitor VisitorFunc) error {
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
func (w *TreeWalker) walkDepthFirst(ctx context.Context, path string, visitor VisitorFunc) error {
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
