package zk

import (
	"context"
	"errors"
	"iter"
	gopath "path"
)

// BatchVisitorFunc is a function that is called for each batch of nodes visited.
type BatchVisitorFunc func(ctx context.Context, paths []string) error

// NewBatchTreeWalker returns a new BatchTreeWalker for the given connection, root path and batch size.
func NewBatchTreeWalker(conn *Conn, path string, batchSize int) *BatchTreeWalker {
	if batchSize <= 0 {
		batchSize = 1 // Must be at least 1.
	}
	return &BatchTreeWalker{
		conn:      conn,
		path:      path,
		batchSize: batchSize,
	}
}

// BatchTreeWalker provides traversal of a tree of nodes rooted at a specific path.
// It fetches children in batches to reduce the number of round trips.
// The batch size is configurable.
type BatchTreeWalker struct {
	conn      *Conn
	path      string
	batchSize int
}

// All returns an iterator over all node paths in the tree and an error function.
// The caller can stop iteration early by breaking out of the range loop.
// After iteration, call the returned error function to check if the walk
// was interrupted by an error (as opposed to completing or being broken out of).
func (w *BatchTreeWalker) All(ctx context.Context) (iter.Seq[string], func() error) {
	var walkErr error
	seq := func(yield func(string) bool) {
		walkErr = w.Walk(ctx, func(_ context.Context, paths []string) error {
			for _, p := range paths {
				if !yield(p) {
					return errBreak
				}
			}
			return nil
		})
		if errors.Is(walkErr, errBreak) {
			walkErr = nil // Break is not an error.
		}
	}
	return seq, func() error { return walkErr }
}

// Walk traverses the tree and calls the visitor function for each batch of nodes visited.
func (w *BatchTreeWalker) Walk(ctx context.Context, visitor BatchVisitorFunc) error {
	return w.walkBatch(ctx, []string{w.path}, visitor)
}

// walkBatch recursively walks the tree in batches.
// It calls the visitor function for each batch of nodes visited.
// It fetches children in batches to reduce the number of round trips.
func (w *BatchTreeWalker) walkBatch(ctx context.Context, paths []string, visitor BatchVisitorFunc) error {
	// Execute the visitor function on all paths.
	if err := visitor(ctx, paths); err != nil {
		return err
	}

	// Fetch children of all paths.
	children, err := w.fetchChildrenBatch(ctx, paths)
	if err != nil {
		return err
	}

	var batch []string

	for i, p := range paths {
		for _, c := range children[i] {
			batch = append(batch, gopath.Join(p, c))

			if len(batch) >= w.batchSize {
				// Recursively walk the batch.
				if err = w.walkBatch(ctx, batch, visitor); err != nil {
					return err
				}
				batch = nil
			}
		}
	}

	if len(batch) > 0 {
		// Recursively walk the last batch.
		if err = w.walkBatch(ctx, batch, visitor); err != nil {
			return err
		}
	}

	return nil
}

// fetchChildrenBatch fetches the children of all paths in a single batch.
func (w *BatchTreeWalker) fetchChildrenBatch(ctx context.Context, paths []string) ([][]string, error) {
	requests := make([]any, len(paths))
	for i, p := range paths {
		requests[i] = &GetChildrenRequest{Path: p}
	}

	responses, err := w.conn.MultiRead(ctx, requests...)
	if err != nil && !errors.Is(err, ErrNoNode) { // Treat ErrNoNode as empty children.
		return nil, err
	}

	children := make([][]string, len(responses))
	for i, r := range responses {
		if errors.Is(r.Error, ErrNoNode) {
			continue // Treat ErrNoNode as empty children.
		}
		children[i] = r.Children
	}

	return children, nil
}
