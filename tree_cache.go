package zk

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultBatchSize = 256
)

// ErrPersistentWatcherStalled is passed to OnSyncError hook whenever the pump reservoir limit is hit.
var ErrPersistentWatcherStalled = fmt.Errorf("persistent watcher has stalled")

func NewTreeCache(conn *Conn, path string, options ...TreeCacheOption) *TreeCache {
	tc := &TreeCache{
		conn:           conn,
		logger:         conn.logger, // By default, use the connection's logger.
		rootPath:       path,
		rootNode:       newTreeCacheNode("", &Stat{}, nil),
		reservoirLimit: defaultReservoirLimit,
		batchSize:      defaultBatchSize,
	}
	for _, option := range options {
		option(tc)
	}
	return tc
}

type TreeCacheOption func(*TreeCache)

// WithTreeCacheIncludeData returns an option to include data in the tree cache.
func WithTreeCacheIncludeData(includeData bool) TreeCacheOption {
	return func(tc *TreeCache) {
		tc.includeData = includeData
	}
}

// WithTreeCacheAbsolutePaths returns an option to use full/absolute paths in the tree cache.
// Normally, the cache reports paths relative to the node it is rooted at.
// For example, if the cache is rooted at "/foo" and "/foo/bar" is created, the cache reports the node as "/bar".
// With absolute paths enabled, the cache reports the node as "/foo/bar".
func WithTreeCacheAbsolutePaths(absolutePaths bool) TreeCacheOption {
	return func(tc *TreeCache) {
		tc.absolutePaths = absolutePaths
	}
}

// WithTreeCacheReservoirLimit returns an option to use the specified reservoir limit in the tree cache.
// The reservoir limit is the absolute maximum number of events that can be queued by watchers before being forcefully closed.
// If the given reservoir limit is <= 0>, the default limit is used.
func WithTreeCacheReservoirLimit(reservoirLimit int) TreeCacheOption {
	return func(tc *TreeCache) {
		if reservoirLimit <= 0 {
			reservoirLimit = defaultReservoirLimit
		}
		tc.reservoirLimit = reservoirLimit
	}
}

// WithTreeCacheBatchSize returns an option to use the specified batch size in the tree cache.
// The batch size determines how many nodes are fetched per request during a tree walk.
// If the given batch size is <= 0>, the default batch size is used.
func WithTreeCacheBatchSize(batchSize int) TreeCacheOption {
	return func(tc *TreeCache) {
		if batchSize <= 0 {
			batchSize = defaultBatchSize
		}
		tc.batchSize = batchSize
	}
}

// WithTreeCacheLogger returns an option that sets the logger to use for the tree cache.
func WithTreeCacheLogger(logger *slog.Logger) TreeCacheOption {
	return func(tc *TreeCache) {
		tc.logger = logger
	}
}

// WithTreeCacheListener returns an option to use the specified listener in the tree cache.
func WithTreeCacheListener(listener TreeCacheListener) TreeCacheOption {
	return func(tc *TreeCache) {
		tc.listener = listener
	}
}

// TreeCacheListener is a listener for tree cache events.
// Events are delivered synchronously, so the listener should not block.
type TreeCacheListener interface {
	// OnSyncStarted is called when the tree cache has started its sync loop.
	OnSyncStarted()

	// OnSyncStopped is called when the tree cache has stopped its sync loop.
	// The error causing the stop is passed as an argument.
	OnSyncStopped(err error)

	// OnSyncError is called when the tree cache encounters an error during sync, prompting a retry.
	OnSyncError(err error)

	// OnTreeSynced is called when the tree cache has completed a full sync of state.
	// This is called once after the tree cache is started, and again after each subsequent sync cycle.
	// A new sync cycle is triggered by connection loss or watch failure.
	OnTreeSynced(elapsed time.Duration)

	// OnNodeCreated is called when a node is created after last full sync.
	OnNodeCreated(path string, data []byte, stat *Stat)

	// OnNodeDeleting is called when a node is about to be deleted from the cache.
	// This is your last chance to get the data for the node before it is deleted.
	// This only works if the cache is configured to include data WithTreeCacheIncludeData.
	// data and stat can be nil if the node was not found in the cache,
	// so, nil handling should be done in the listener
	OnNodeDeleting(path string, data []byte, stat *Stat)

	// OnNodeDeleted is called when a node is deleted after last full sync.
	OnNodeDeleted(path string)

	// OnNodeDataChanged is called when a node's data is changed after last full sync.
	OnNodeDataChanged(path string, data []byte, stat *Stat)
}

// TreeCacheListenerFuncs is a convenience type that implements TreeCacheListener with function callbacks.
// Any callback that is nil is ignored.
type TreeCacheListenerFuncs struct {
	OnSyncStartedFunc     func()
	OnSyncStoppedFunc     func(err error)
	OnSyncErrorFunc       func(err error)
	OnTreeSyncedFunc      func(elapsed time.Duration)
	OnNodeCreatedFunc     func(path string, data []byte, stat *Stat)
	OnNodeDeletingFunc    func(path string, data []byte, stat *Stat)
	OnNodeDeletedFunc     func(path string)
	OnNodeDataChangedFunc func(path string, data []byte, stat *Stat)
}

func (l *TreeCacheListenerFuncs) OnSyncStarted() {
	if l.OnSyncStartedFunc != nil {
		l.OnSyncStartedFunc()
	}
}

func (l *TreeCacheListenerFuncs) OnSyncStopped(err error) {
	if l.OnSyncStoppedFunc != nil {
		l.OnSyncStoppedFunc(err)
	}
}

func (l *TreeCacheListenerFuncs) OnSyncError(err error) {
	if l.OnSyncErrorFunc != nil {
		l.OnSyncErrorFunc(err)
	}
}

func (l *TreeCacheListenerFuncs) OnTreeSynced(elapsed time.Duration) {
	if l.OnTreeSyncedFunc != nil {
		l.OnTreeSyncedFunc(elapsed)
	}
}

func (l *TreeCacheListenerFuncs) OnNodeCreated(path string, data []byte, stat *Stat) {
	if l.OnNodeCreatedFunc != nil {
		l.OnNodeCreatedFunc(path, data, stat)
	}
}

func (l *TreeCacheListenerFuncs) OnNodeDeleting(path string, data []byte, stat *Stat) {
	if l.OnNodeDeletingFunc != nil {
		l.OnNodeDeletingFunc(path, data, stat)
	}
}

func (l *TreeCacheListenerFuncs) OnNodeDeleted(path string) {
	if l.OnNodeDeletedFunc != nil {
		l.OnNodeDeletedFunc(path)
	}
}

func (l *TreeCacheListenerFuncs) OnNodeDataChanged(path string, data []byte, stat *Stat) {
	if l.OnNodeDataChangedFunc != nil {
		l.OnNodeDataChangedFunc(path, data, stat)
	}
}

type TreeCache struct {
	conn              *Conn
	logger            *slog.Logger
	rootPath          string         // Path to root node being cached.
	includeData       bool           // true to include data in cache; false to omit.
	absolutePaths     bool           // true to report full/absolute paths; false to report paths relative to rootPath.
	reservoirLimit    int            // The reservoir size limit for persistent watchers. Defaults to defaultReservoirLimit.
	batchSize         int            // The batch size for fetching nodes during a tree walk. Defaults to defaultBatchSize.
	rootNode          *treeCacheNode // Root node of the tree.
	treeMutex         sync.RWMutex   // Protects tree state (rootNode and all descendants).
	syncing           bool           // Set to true while Sync() is running; false otherwise.
	initialSyncDone   bool           // Set to true after the first full tree sync is complete.
	initialSyncResult chan error     // Closed when initial sync completes or fails; holds error if failed.
	syncMutex         sync.Mutex     // Protects sync state.
	listener          TreeCacheListener
}

func (tc *TreeCache) Sync(ctx context.Context) (err error) {
	tc.syncMutex.Lock()

	if tc.syncing { // Protect against concurrent calls to Sync().
		tc.syncMutex.Unlock()
		return fmt.Errorf("tree cache is already syncing")
	}

	tc.syncing = true
	tc.initialSyncDone = false
	tc.initialSyncResult = make(chan error, 1)

	tc.syncMutex.Unlock()

	defer func() {
		tc.syncMutex.Lock()
		defer tc.syncMutex.Unlock()

		tc.syncing = false

		if !tc.initialSyncDone {
			if err != nil {
				tc.initialSyncResult <- err
			} else {
				tc.initialSyncResult <- fmt.Errorf("tree cache stopped syncing")
			}
			close(tc.initialSyncResult) // Unblock anything waiting on initial sync.
		}

		if tc.listener != nil {
			tc.listener.OnSyncStopped(err)
		}
	}()

	if tc.listener != nil {
		tc.listener.OnSyncStarted()
	}

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
		if found, _, existsCh, err := tc.conn.ExistsW(ctx, tc.rootPath); !found || err != nil {
			if err != nil {
				tc.logger.Error("failed to check if path exists", "error", err)
				continue // Re-check conditions.
			}
			// Wait for the path to be created (up to 10 seconds, then re-check conditions).
			tc.logger.Info("waiting for path to exist", "path", tc.rootPath)
			ctxWait, waitCancel := context.WithTimeout(ctx, 10*time.Second)
			select {
			case <-existsCh:
			case <-ctxWait.Done():
			}
			waitCancel()
			continue //  Re-check conditions.
		}

		if err := tc.doSync(ctx); err != nil {
			if tc.listener != nil {
				tc.listener.OnSyncError(err)
			}
			tc.logger.Error("failed to sync tree cache", "error", err)
		}

		// Loop back to restart next sync cycle.
	}
}

func (tc *TreeCache) doSync(ctx context.Context) error {
	stalled := &atomic.Value{}
	stalled.Store(false)
	// Start a recursive watch, so we do not miss any changes.
	// We'll catch up with the changes after the initial sync.
	watchCh, err := tc.conn.AddWatch(ctx, tc.rootPath, true,
		WithWatcherInvalidateOnDisconnect(),
		WithWatcherReservoirLimit(tc.reservoirLimit),
		WithStallCallback(func() {
			stalled.Store(true)
		}))
	if err != nil {
		return err
	}
	defer func() {
		_ = tc.conn.RemoveWatch(ctx, watchCh)
	}()

	// Holds the new tree state, which we must populate before replacing the current tree (if any).
	newRoot := newTreeCacheNode("", &Stat{}, nil)

	// This function is called from tree walk to add nodes to the new tree.
	// Note: Not thread-safe, but we don't expect it to be called concurrently.
	batchAddNodes := func(ctx context.Context, paths []string) error {
		ops := make([]any, len(paths))
		for i, p := range paths {
			// Note: We have to fetch data regardless of tc.includeData, because we need the node's stat.
			// If `GetChildren2` or `Exists` were supported for multi-read, then we could avoid fetching data.
			ops[i] = &GetDataRequest{Path: p}
		}

		// Fetch all the data in a single batch.
		resps, err := tc.conn.MultiRead(ctx, ops...)
		if err != nil && !errors.Is(err, ErrNoNode) { // Ignore ErrNoNode.
			return err
		}

		for i, r := range resps {
			if r.Error != nil {
				if errors.Is(r.Error, ErrNoNode) {
					continue // Skip missing node.
				}
				return r.Error
			}
			relPath := paths[i][len(tc.rootPath):]
			n := newRoot.ensurePath(relPath)
			n.stat = r.Stat
			if tc.includeData { // Only retain data if requested.
				n.data = r.Data
			}
		}

		return nil
	}

	syncStartTime := time.Now()

	// Walk from rootPath to populate our new tree state.
	if err = tc.conn.BatchWalker(tc.rootPath, tc.batchSize).Walk(ctx, batchAddNodes); err != nil {
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
		close(tc.initialSyncResult)
	}
	tc.syncMutex.Unlock()

	syncElapsedTime := time.Since(syncStartTime)
	tc.logger.Info("synced tree cache", "elapsed", syncElapsedTime)
	if tc.listener != nil {
		tc.listener.OnTreeSynced(syncElapsedTime)
	}

	// Process watch events until the context is canceled, watching is stopped, or an error occurs.
	for {
		select {
		case e, ok := <-watchCh:
			if !ok {
				if stalled.Load().(bool) {
					return ErrPersistentWatcherStalled
				}
				return fmt.Errorf("watch channel closed unexpectedly")
			}
			relPath := e.Path[len(tc.rootPath):]
			switch e.Type {
			case EventNodeCreated:
				if relPath != "/" {
					// Update stat of parent to reflect new child count.
					found, stat, err := tc.conn.Exists(ctx, filepath.Dir(e.Path))
					if err != nil {
						return err // We are out of sync.
					}
					if found {
						tc.updateStat(filepath.Dir(relPath), stat)
					}
				}
				if tc.includeData {
					data, stat, err := tc.conn.Get(ctx, e.Path)
					if err != nil {
						if errors.Is(err, ErrNoNode) {
							continue // We'll get an EventNodeDeleted later.
						}
						return err // We are out of sync.
					}
					tc.put(relPath, stat, data)
					if tc.listener != nil {
						tc.listener.OnNodeCreated(relPath, data, stat)
					}
				} else {
					found, stat, err := tc.conn.Exists(ctx, e.Path)
					if err != nil {
						return err // We are out of sync.
					}
					if found {
						tc.put(relPath, stat, nil)
						if tc.listener != nil {
							tc.listener.OnNodeCreated(relPath, nil, stat)
						}
					} // else, we'll get an EventNodeDeleted later.
				}
			case EventNodeDataChanged:
				if tc.includeData {
					data, stat, err := tc.conn.Get(ctx, e.Path)
					if err != nil {
						if errors.Is(err, ErrNoNode) {
							continue // We'll get an EventNodeDeleted later.
						}
						return err // We are out of sync.
					}
					tc.put(relPath, stat, data)
					if tc.listener != nil {
						tc.listener.OnNodeDataChanged(relPath, data, stat)
					}
				} else {
					found, stat, err := tc.conn.Exists(ctx, e.Path)
					if err != nil {
						return err // We are out of sync.
					}
					if found {
						tc.put(relPath, stat, nil)
						if tc.listener != nil {
							tc.listener.OnNodeDataChanged(relPath, nil, stat)
						}
					} // else, we'll get an EventNodeDeleted later.
				}
			case EventNodeDeleted:
				if relPath != "/" {
					// Update stat of parent to reflect new child count.
					found, stat, err := tc.conn.Exists(ctx, filepath.Dir(e.Path))
					if err != nil {
						return err
					}
					if found {
						tc.updateStat(filepath.Dir(relPath), stat)
					} // else, we'll get an EventNodeDeleted later.
				}
				if tc.includeData && tc.listener != nil {
					dataPath := relPath
					if tc.absolutePaths {
						dataPath = e.Path
					}
					// we ignore the ErrNoNode here because the node may have not been created in the cache yet
					// but we received the delete event, so, nil handling should be done in the listener
					data, stat, err := tc.Get(dataPath)
					if err != nil && !errors.Is(err, ErrNoNode) {
						return err
					}
					tc.listener.OnNodeDeleting(relPath, data, stat)
				}
				tc.delete(relPath)
				if tc.listener != nil {
					tc.listener.OnNodeDeleted(relPath)
				}
			case EventNotWatching:
				return fmt.Errorf("watch was closed by server")
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (tc *TreeCache) waitForSession(ctx context.Context) error {
	for tc.conn.State() != StateHasSession {
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

	// Get a ref to the initialSyncResult, so we can release the lock before waiting on it.
	syncCh := tc.initialSyncResult
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

	children := slices.Collect(maps.Keys(n.children))

	return children, n.stat, nil
}

func (tc *TreeCache) Walker(path string, order TraversalOrder) *TreeWalker {
	fetcher := func(_ context.Context, path string) ([]string, *Stat, error) {
		return tc.Children(path)
	}
	return NewTreeWalker(fetcher, path, order)
}

// toInternalPath translates the given external path to a path relative to root node of the cache.
// If absolutePaths is true, then the external path is expected to be prefixed by rootPath.
// Otherwise, the external path is expected to already be relative to rootPath (but still prefixed by a forward slash).
func (tc *TreeCache) toInternalPath(externalPath string) (string, error) {
	if tc.absolutePaths {
		// We expect externalPath to be prefixed by rootPath.
		internalPath, ok := strings.CutPrefix(externalPath, tc.rootPath)
		if !ok {
			return "", fmt.Errorf("path %q was outside of cache scope: %q", externalPath, tc.rootPath)
		}
		// Ex: rootPath="/foo", externalPath="/foo/bar" => internalPath="/bar"
		return internalPath, nil
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
	for name := range strings.SplitSeq(path, "/") {
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
	for name := range strings.SplitSeq(path, "/") {
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
	for name := range strings.SplitSeq(path, "/") {
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
