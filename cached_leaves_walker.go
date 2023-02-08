package zk

import (
	gopath "path"
	"strings"
	"sync"
	"sync/atomic"
)

// CachedLeavesWalker is an helper to have fast WalkLeaves by keeping the leaves in memory.
// Leaves are kept in sync with Zookeeper using a recursive watch.
// In case the CachedLeavesWalker looses the watch, WalkLeaves will return an ErrNoWatcher.
// In such case, the walker should be re-instantiated.
// Close() should be called to properly terminate the walker.
type CachedLeavesWalker struct {
	conn   *Conn
	events <-chan Event
	active int32
	tree   cachedLeavesTreeNode
	lock   sync.RWMutex
}

// NewCachedLeavesWalker instanciate a new walker.
// Initial leaves sync is performed during this function,
// it may be slow depending on the size of the path tree.
func NewCachedLeavesWalker(conn *Conn, path string) (*CachedLeavesWalker, error) {
	events, err := conn.AddWatch(path, true)
	if err != nil {
		return nil, err
	}

	w := &CachedLeavesWalker{
		conn:   conn,
		events: events,
		tree:   make(cachedLeavesTreeNode),
		lock:   sync.RWMutex{},
	}

	go w.eventLoop()
	if err = conn.TreeWalker(path).
		BreadthFirst().
		Concurrency(8). // This is just randomly chosen.
		LeavesOnly().
		Walk(func(p string, _ *Stat) error {
			w.lock.Lock()
			w.tree.ensurePathPresent(p)
			w.lock.Unlock()
			return nil
		}); err != nil {
		if cerr := w.Close(); cerr != nil {
			w.conn.logger.Printf("failed to close CachedLeavesWalker: %v", cerr)
		}
		return nil, err
	}
	return w, nil
}

// Close ensure we properly stop watching.
func (w *CachedLeavesWalker) Close() error {
	if atomic.LoadInt32(&w.active) != 1 {
		if err := w.conn.RemoveWatch(w.events); err != nil {
			return err
		}
	}
	return nil
}

// eventLoop processing the watch events.
func (w *CachedLeavesWalker) eventLoop() {
	atomic.StoreInt32(&w.active, 1)
	defer atomic.StoreInt32(&w.active, 0)
	for e := range w.events {
		w.lock.Lock()
		switch e.Type {
		case EventNodeCreated, EventNodeDataChanged:
			w.tree.ensurePathPresent(e.Path)
		case EventNodeDeleted:
			w.tree.ensurePathAbsent(e.Path)
		}
		w.lock.Unlock()
	}
}

// WalkLeaves will call the visitor functions for each currently known leaves.
// Keep in mind that leaves sync is done asynchronously using a watcher.
// There may be a delay between a node creation/deletion and the cached leaves being updated.
func (w *CachedLeavesWalker) WalkLeaves(visitor func(p string) error) error {
	if atomic.LoadInt32(&w.active) != 1 {
		return ErrNoWatcher
	}
	w.lock.RLock()
	defer w.lock.RUnlock()
	return w.walkLeaves("/", w.tree, visitor)
}

func (w *CachedLeavesWalker) walkLeaves(p string, tree cachedLeavesTreeNode, visitor func(p string) error) error {
	if len(tree) > 0 {
		for l := range tree {
			if err := w.walkLeaves(gopath.Join(p, l), tree[l], visitor); err != nil {
				return err
			}
		}
		return nil
	}
	return visitor(p)
}

// cachedLeavesTreeNode represent an in memory znode equivalent.
type cachedLeavesTreeNode map[string]cachedLeavesTreeNode

// ensurePathPresent will make sure we have the proper in-memory tree for a given path.
func (n cachedLeavesTreeNode) ensurePathPresent(path string) {
	nodes := strings.Split(path[1:], "/")
	n.setNodes(nodes)
}

// ensurePathPresent will make sure we have remove the in-memory tree for a given path.
func (n cachedLeavesTreeNode) ensurePathAbsent(path string) {
	nodes := strings.Split(path[1:], "/")
	n.deleteNodes(nodes)
}

// setNodes recursively apply nodes elements to the tree.
func (n cachedLeavesTreeNode) setNodes(nodes []string) {
	if len(nodes) == 0 {
		return
	}

	if _, ok := n[nodes[0]]; !ok {
		n[nodes[0]] = make(cachedLeavesTreeNode)
	}
	n[nodes[0]].setNodes(nodes[1:])
}

// setNodes recursively remove nodes elements from the tree.
func (n cachedLeavesTreeNode) deleteNodes(nodes []string) {
	l := len(nodes)
	switch l {
	case 0: // Safety, should never happen.
		return
	case 1:
		if nodes[0] == "" {
			return // Don't delete root
		}
		delete(n, nodes[0])
	default:
		n[nodes[0]].deleteNodes(nodes[1:])
	}
}
