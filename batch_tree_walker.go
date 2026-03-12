package zk

import (
	"context"
	"errors"
	"iter"
	gopath "path"
)

// BatchVisitorFunc is a function that is called for each batch of nodes visited.
type BatchVisitorFunc func(paths []string) error

// BatchVisitorCtxFunc is like BatchVisitorFunc, but it takes a context.
type BatchVisitorCtxFunc func(ctx context.Context, paths []string) error

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

// Walk begins traversing the tree and calls the visitor function for each node visited.
func (w *BatchTreeWalker) Walk(visitor BatchVisitorFunc) error {
	vc := func(ctx context.Context, paths []string) error {
		return visitor(paths)
	}
	return w.WalkCtx(context.Background(), vc)
}

func (w *BatchTreeWalker) WalkCtx(ctx context.Context, visitor BatchVisitorCtxFunc) error {
	return w.walkBatch(ctx, []string{w.path}, visitor)
}

// WalkChan begins traversing the tree and sends the results to the returned channel.
// The channel will be buffered with the given size.
// The channel is closed when the traversal is complete.
// If an error occurs, an error event will be sent to the channel before it is closed.
func (w *BatchTreeWalker) WalkChan(bufferSize int) <-chan VisitEvent {
	return w.WalkChanCtx(context.Background(), bufferSize)
}

// WalkChanCtx is like WalkChan, but it takes a context that can be used to cancel the walk.
func (w *BatchTreeWalker) WalkChanCtx(ctx context.Context, bufferSize int) <-chan VisitEvent {
	ch := make(chan VisitEvent, bufferSize)
	visitor := func(ctx context.Context, paths []string) error {
		for _, p := range paths {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case ch <- VisitEvent{Path: p}:
			}
		}
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

// All returns an iterator over all node paths in the tree.
// It uses context.Background internally.
func (w *BatchTreeWalker) All() iter.Seq[string] {
	return w.AllCtx(context.Background())
}

// AllCtx returns an iterator over all node paths in the tree.
// The caller can stop iteration early by breaking out of the range loop.
func (w *BatchTreeWalker) AllCtx(ctx context.Context) iter.Seq[string] {
	return func(yield func(string) bool) {
		err := w.WalkCtx(ctx, func(_ context.Context, paths []string) error {
			for _, p := range paths {
				if !yield(p) {
					return errBreak
				}
			}
			return nil
		})
		_ = err // errBreak is expected when the caller breaks out of the range loop.
	}
}

// walkBatch recursively walks the tree in batches.
// It calls the visitor function for each batch of nodes visited.
// It fetches children in batches to reduce the number of round trips.
func (w *BatchTreeWalker) walkBatch(ctx context.Context, paths []string, visitor BatchVisitorCtxFunc) error {
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

	responses, err := w.conn.MultiReadCtx(ctx, requests...)
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
