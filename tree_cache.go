package zk

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func NewTreeCache(conn *Conn, path string, options ...TreeCacheOption) *TreeCache {
	tc := &TreeCache{
		conn:     conn,
		logger:   conn.logger, // By default, use the connection's logger.
		rootPath: path,
		rootNode: newTreeCacheNode("", &Stat{}, nil),
	}
	for _, option := range options {
		option(tc)
	}
	return tc
}

type TreeCacheOption func(*TreeCache)

// TreeCacheLogger returns an option that sets the logger to use for the tree cache.
func TreeCacheLogger(logger Logger) TreeCacheOption {
	return func(tc *TreeCache) {
		tc.logger = logger
	}
}

// TreeCacheIncludeData returns an option to include data in the tree cache.
func TreeCacheIncludeData(includeData bool) TreeCacheOption {
	return func(tc *TreeCache) {
		tc.includeData = includeData
	}
}

// TreeCacheAbsolutePaths returns an option to use full/absolute paths in the tree cache.
// Normally, the cache reports paths relative to the node it is rooted at.
// For example, if the cache is rooted at "/foo" and "/foo/bar" is created, the cache reports the node as "/bar".
// With absolute paths enabled, the cache reports the node as "/foo/bar".
func TreeCacheAbsolutePaths(absolutePaths bool) TreeCacheOption {
	return func(tc *TreeCache) {
		tc.absolutePaths = absolutePaths
	}
}

type TreeCache struct {
	conn            *Conn
	logger          Logger
	rootPath        string         // Path to root node being cached.
	includeData     bool           // true to include data in cache; false to omit.
	absolutePaths   bool           // true to report full/absolute paths; false to report paths relative to rootPath.
	rootNode        *treeCacheNode // Root node of the tree.
	treeMutex       sync.RWMutex   // Protects tree state (rootNode and all descendants).
	syncing         bool           // Set to true while Sync() is running; false otherwise.
	initialSyncDone bool           // Set to true after the first full tree sync is complete.
	initialSyncCh   chan error     // Closed when initial sync completes or fails; holds error if failed.
	syncMutex       sync.Mutex     // Protects sync state.

}

func (tc *TreeCache) Sync(ctx context.Context) (err error) {
	tc.syncMutex.Lock()

	if tc.syncing { // Protect against concurrent calls to Sync().
		tc.syncMutex.Unlock()
		return fmt.Errorf("tree cache is already syncing")
	}

	tc.syncing = true
	tc.initialSyncDone = false
	tc.initialSyncCh = make(chan error, 1)

	tc.syncMutex.Unlock()

	defer func() {
		tc.syncMutex.Lock()
		defer tc.syncMutex.Unlock()

		tc.syncing = false
		if !tc.initialSyncDone {
			if err != nil {
				tc.initialSyncCh <- err
			} else {
				tc.initialSyncCh <- fmt.Errorf("tree cache stopped syncing")
			}
			close(tc.initialSyncCh) // Unblock anything waiting on initial sync.
		}
	}()

	// Loop until the context is canceled or the connection is closed.
	for {
		if ctx.Err() != nil {
			return ctx.Err() // Context was canceled - this is fatal.
		}

		// Wait for connection to establish a session.
		if err := tc.waitForSession(ctx); err != nil {
			return err // Suggests the connection was closed - this is fatal.
		}

		// Wait for path to exist.
		if found, _, ch, err := tc.conn.ExistsWCtx(ctx, tc.rootPath); !found || err != nil {
			if err != nil {
				tc.logger.Printf("failed to check if path exists: %v", err)
				continue // Re-check conditions.
			}
			tc.logger.Printf("path does not exist: %s", tc.rootPath)
			// Wait for the path to be created.
			select {
			case <-ch:
			case <-ctx.Done():
			}
			continue //  Re-check conditions.
		}

		if err := tc.doSync(ctx); err != nil {
			tc.logger.Printf("failed to sync tree cache: %v", err)
		}

		// Loop back to restart sync.
	}
}

func (tc *TreeCache) doSync(ctx context.Context) error {
	// Start a recursive watch, so we do not miss any changes.
	// We'll catch up with the changes after the initial sync.
	watchCh, err := tc.conn.AddWatchCtx(ctx, tc.rootPath, true)
	if err != nil {
		return err
	}
	defer func() {
		_ = tc.conn.RemoveWatch(watchCh)
	}()

	// Populate a new tree with a parallel, breadth-first traversal.
	// We won't touch the existing tree until we're done, after which we'll atomically swap it.
	newRoot := newTreeCacheNode("", &Stat{}, nil)
	newRootMutex := sync.Mutex{} // Protects newRoot and all descendants during parallel traversal.
	err = tc.conn.TreeWalker(tc.rootPath).
		BreadthFirstParallel().
		IncludeRoot(true).
		WalkCtx(ctx, func(ctx context.Context, path string, stat *Stat) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}

			subPath := path[len(tc.rootPath):]
			var data []byte

			if tc.includeData {
				var err error
				if data, stat, err = tc.conn.GetCtx(ctx, path); err != nil {
					if err == ErrNoNode {
						return nil // Ignore race condition.
					}
					return err
				}
			}

			newRootMutex.Lock()
			defer newRootMutex.Unlock()

			n := newRoot.ensurePath(subPath)
			n.stat = stat
			n.data = data

			return nil
		})
	if err != nil {
		return err
	}

	// Swap the new tree into place.
	tc.treeMutex.Lock()
	tc.rootNode = newRoot
	tc.treeMutex.Unlock()

	tc.syncMutex.Lock()
	if !tc.initialSyncDone {
		// Signal to waiters in WaitForInitialSync() that initial sync has completed.
		tc.initialSyncDone = true
		close(tc.initialSyncCh)
	}
	tc.syncMutex.Unlock()

	// Process watch events until the context is canceled, watching is stopped, or an error occurs.
	for {
		select {
		case e, ok := <-watchCh:
			if !ok {
				return fmt.Errorf("watch channel closed unexpectedly")
			}
			subPath := e.Path[len(tc.rootPath):]
			switch e.Type {
			case EventNodeCreated:
				if subPath != "/" {
					// Update stat of parent to reflect new child count.
					found, stat, err := tc.conn.ExistsCtx(ctx, filepath.Dir(e.Path))
					if err != nil {
						return err // We are out of sync.
					}
					if found {
						tc.updateStat(filepath.Dir(subPath), stat)
					}
				}
				fallthrough // Also update stat and data of changed node.
			case EventNodeDataChanged:
				if tc.includeData {
					data, stat, err := tc.conn.GetCtx(ctx, e.Path)
					if err != nil {
						if err == ErrNoNode {
							continue // We'll get an EventNodeDeleted later.
						}
						return err // We are out of sync.
					}
					tc.put(subPath, stat, data)
				} else {
					found, stat, err := tc.conn.ExistsCtx(ctx, e.Path)
					if err != nil {
						return err // We are out of sync.
					}
					if found {
						tc.put(subPath, stat, nil)
					} // else, we'll get an EventNodeDeleted later.
				}
			case EventNodeDeleted:
				if subPath != "/" {
					// Update stat of parent to reflect new child count.
					found, stat, err := tc.conn.ExistsCtx(ctx, filepath.Dir(e.Path))
					if err != nil {
						return err
					}
					if found {
						tc.updateStat(filepath.Dir(subPath), stat)
					} // else, we'll get an EventNodeDeleted later.
				}
				tc.delete(subPath)
			case EventNotWatching:
				return fmt.Errorf("watch was closed by server")
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (tc *TreeCache) waitForSession(ctx context.Context) error {
	for {
		if tc.conn.State() == StateHasSession {
			break
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tc.conn.shouldQuit:
			return ErrClosing
		case <-time.After(100 * time.Millisecond):
		}
	}

	return nil
}

func (tc *TreeCache) put(path string, stat *Stat, data []byte) {
	tc.treeMutex.Lock()
	defer tc.treeMutex.Unlock()

	n := tc.rootNode.ensurePath(path)
	n.stat = stat
	n.data = data
}

func (tc *TreeCache) updateStat(path string, stat *Stat) {
	tc.treeMutex.Lock()
	defer tc.treeMutex.Unlock()

	n, ok := tc.rootNode.getPath(path)
	if ok {
		n.stat = stat
	}
}

func (tc *TreeCache) delete(path string) {
	tc.treeMutex.Lock()
	defer tc.treeMutex.Unlock()

	tc.rootNode.deletePath(path)
}

// WaitForInitialSync will wait for the cache to start and complete an initial sync of the tree.
// This method will return when any of the following conditions are met (whichever occurs first):
//  1. The initial sync completes,
//  2. The Sync() method returns before the initial sync completes, or
//  3. The given context is cancelled / timed-out.
//
// In cases (2) and (3), an error will be returned indicating the cause.
func (tc *TreeCache) WaitForInitialSync(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		tc.syncMutex.Lock()

		if !tc.syncing {
			// Sync has not started, so wait a bit and try again.
			tc.syncMutex.Unlock()
			select {
			case <-time.After(100 * time.Millisecond):
			case <-ctx.Done():
			}
			continue
		}

		if tc.initialSyncDone {
			tc.syncMutex.Unlock()
			return nil // Sync has already completed.
		}

		break // Break loop with lock held.
	}

	// Get a ref to the initialSyncCh, so we can release the lock before waiting on it.
	syncCh := tc.initialSyncCh
	tc.syncMutex.Unlock()

	// Wait for the initial sync to complete/abort, or context to be canceled; whichever happens first.
	select {
	case e, ok := <-syncCh:
		if ok && e != nil {
			return e // Sync aborted with error.
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func (tc *TreeCache) Exists(path string) (bool, *Stat, error) {
	internalPath, err := tc.toInternalPath(path)
	if err != nil {
		return false, nil, err
	}

	tc.treeMutex.RLock()
	defer tc.treeMutex.RUnlock()

	n, ok := tc.rootNode.getPath(internalPath)
	if !ok {
		return false, nil, nil
	}

	return true, n.stat, nil
}

func (tc *TreeCache) Get(path string) ([]byte, *Stat, error) {
	internalPath, err := tc.toInternalPath(path)
	if err != nil {
		return nil, nil, err
	}

	tc.treeMutex.RLock()
	defer tc.treeMutex.RUnlock()

	n, ok := tc.rootNode.getPath(internalPath)
	if !ok {
		return nil, nil, ErrNoNode
	}

	return n.data, n.stat, nil
}

func (tc *TreeCache) Children(path string) ([]string, *Stat, error) {
	internalPath, err := tc.toInternalPath(path)
	if err != nil {
		return nil, nil, err
	}

	tc.treeMutex.RLock()
	defer tc.treeMutex.RUnlock()

	n, ok := tc.rootNode.getPath(internalPath)
	if !ok {
		return nil, nil, ErrNoNode
	}

	var children []string
	for name := range n.children {
		children = append(children, name)
	}

	return children, n.stat, nil
}

func (tc *TreeCache) Walker(path string) TreeWalker {
	fetcher := func(_ context.Context, path string) ([]string, *Stat, error) {
		return tc.Children(path)
	}
	return InitTreeWalker(fetcher, path)
}

// toInternalPath translates the given external path to a path relative to root node of the cache.
// If absolutePaths is true, then the external path is expected to be prefixed by rootPath.
// Otherwise, the external path is expected to already be relative to rootPath (but still prefixed by a forward slash).
func (tc *TreeCache) toInternalPath(externalPath string) (string, error) {
	if tc.absolutePaths {
		// We expect externalPath to be prefixed by rootPath.
		if !strings.HasPrefix(externalPath, tc.rootPath) {
			return "", fmt.Errorf("path was outside of cache scope: %s", tc.rootPath)
		}
		// Ex: rootPath="/foo", externalPath="/foo/bar" => internalPath="/bar"
		return externalPath[len(tc.rootPath):], nil
	}
	// Path assumed to be relative to rootPath (ie: internalPath == externalPath).
	// Ex: rootPath="/foo", externalPath="/bar" => internalPath="/bar"
	return externalPath, nil
}

func newTreeCacheNode(name string, stat *Stat, data []byte) *treeCacheNode {
	return &treeCacheNode{
		name: name,
		stat: stat,
		data: data,
	}
}

type treeCacheNode struct {
	name     string
	stat     *Stat
	data     []byte
	children map[string]*treeCacheNode
}

func (tcn *treeCacheNode) getPath(path string) (*treeCacheNode, bool) {
	n := tcn
	for _, name := range strings.Split(path, "/") {
		if name == "" {
			continue
		}
		var ok bool
		n, ok = n.children[name]
		if !ok {
			return nil, false
		}
	}

	return n, true
}

func (tcn *treeCacheNode) ensurePath(path string) *treeCacheNode {
	n := tcn
	for _, name := range strings.Split(path, "/") {
		if name == "" {
			continue
		}
		n = n.ensureChild(name)
	}
	return n
}

func (tcn *treeCacheNode) ensureChild(name string) *treeCacheNode {
	c, ok := tcn.children[name] // Note: It is safe to read from a nil map.
	if !ok {
		c = newTreeCacheNode(name, &Stat{}, nil)
		if tcn.children == nil {
			tcn.children = make(map[string]*treeCacheNode)
		}
		tcn.children[name] = c
	}
	return c
}

func (tcn *treeCacheNode) deletePath(path string) {
	n := tcn
	prev := n
	for _, name := range strings.Split(path, "/") {
		if name == "" {
			continue
		}
		c, ok := n.children[name]
		if !ok {
			return
		}
		prev = n
		n = c
	}
	if prev != n {
		delete(prev.children, n.name)
	}
}
