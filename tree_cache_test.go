package zk

import (
	"context"
	"sort"
	"strconv"
	"testing"
	"time"
)

func TestTreeCache_ConsistentAfterInitialSync_WithData(t *testing.T) {
	initialNodes := []struct {
		realPath    string
		cachePath   string
		data        string
		numChildren int32
	}{
		{
			realPath:    "/test-tree-cache",
			cachePath:   "/",
			data:        "root",
			numChildren: 2,
		},
		{
			realPath:    "/test-tree-cache/child1",
			cachePath:   "/child1",
			data:        "child1",
			numChildren: 1,
		},
		{
			realPath:    "/test-tree-cache/child1/child1_1",
			cachePath:   "/child1/child1_1",
			data:        "child1_1",
			numChildren: 0,
		},
		{
			realPath:    "/test-tree-cache/child2",
			cachePath:   "/child2",
			data:        "child2",
			numChildren: 1,
		},
		{
			realPath:    "/test-tree-cache/child2/child2_1",
			cachePath:   "/child2/child2_1",
			data:        "child2_1",
			numChildren: 0,
		},
	}

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			for _, n := range initialNodes {
				_, err := c.Create(n.realPath, []byte(n.data), 0, WorldACL(PermAll))
				if err != nil {
					t.Fatalf("failed to create node %s: %v", n.realPath, err)
				}
			}

			// By default, paths a relative to root.
			cache := NewTreeCache(c, "/test-tree-cache",
				WithTreeCacheIncludeData(true))
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()

			syncErrCh := make(chan error, 1)

			// Start syncing cache in the background.
			go func() {
				defer close(syncErrCh)
				syncErrCh <- cache.Sync(ctx)
			}()

			// Wait for the first full sync to complete.
			err := cache.WaitForInitialSync(ctx)
			if err != nil {
				t.Fatalf("initial cache sync failed: %v", err)
			}

			// Check that the cache contains the expected nodes.
			for _, n := range initialNodes {
				data, stat, err := cache.Get(n.cachePath)
				if err != nil {
					t.Fatalf("failed to get cache node %s: %v", n.cachePath, err)
				}
				if string(data) != n.data {
					t.Fatalf("cache node %s data mismatch: expected %s, got %s", n.cachePath, n.data, string(data))
				}
				if stat.NumChildren != n.numChildren {
					t.Fatalf("cache node %s numChildren mismatch: expected %d, got %d", n.cachePath, n.numChildren, stat.NumChildren)
				}
			}

			cancel()
			if err := <-syncErrCh; err != context.Canceled {
				t.Fatalf("expected context.Canceled, got %v", err)
			}
		})
	})
}

func TestTreeCache_ConsistentAfterInitialSync_NoData(t *testing.T) {
	initialNodes := []struct {
		realPath    string
		cachePath   string
		numChildren int32
	}{
		{
			realPath:    "/test-tree-cache",
			cachePath:   "/",
			numChildren: 2,
		},
		{
			realPath:    "/test-tree-cache/child1",
			cachePath:   "/child1",
			numChildren: 1,
		},
		{
			realPath:    "/test-tree-cache/child1/child1_1",
			cachePath:   "/child1/child1_1",
			numChildren: 0,
		},
		{
			realPath:    "/test-tree-cache/child2",
			cachePath:   "/child2",
			numChildren: 1,
		},
		{
			realPath:    "/test-tree-cache/child2/child2_1",
			cachePath:   "/child2/child2_1",
			numChildren: 0,
		},
	}

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			for _, n := range initialNodes {
				_, err := c.Create(n.realPath, []byte("ignore me"), 0, WorldACL(PermAll))
				if err != nil {
					t.Fatalf("failed to create node %s: %v", n.realPath, err)
				}
			}

			// By default, paths a relative to root.
			cache := NewTreeCache(c, "/test-tree-cache",
				WithTreeCacheIncludeData(false)) // <-- no data
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()

			syncErrCh := make(chan error, 1)

			// Start syncing cache in the background.
			go func() {
				defer close(syncErrCh)
				syncErrCh <- cache.Sync(ctx)
			}()

			// Wait for the first full sync to complete.
			err := cache.WaitForInitialSync(ctx)
			if err != nil {
				t.Fatalf("initial cache sync failed: %v", err)
			}

			// Check that the cache contains the expected nodes.
			for _, n := range initialNodes {
				data, stat, err := cache.Get(n.cachePath)
				if err != nil {
					t.Fatalf("failed to get cache node %s: %v", n.cachePath, err)
				}
				if data != nil {
					t.Fatalf("cache node %s data mismatch: expected nil, got %s", n.cachePath, string(data))
				}
				if stat.NumChildren != n.numChildren {
					t.Fatalf("cache node %s numChildren mismatch: expected %d, got %d", n.cachePath, n.numChildren, stat.NumChildren)
				}
			}

			cancel()
			if err := <-syncErrCh; err != context.Canceled {
				t.Fatalf("expected context.Canceled, got %v", err)
			}
		})
	})
}

func TestTreeCache_OpsWithRelativePaths(t *testing.T) {
	initialNodes := []struct {
		realPath string
		data     string
	}{
		{
			realPath: "/test-tree-cache",
			data:     "root",
		},
		{
			realPath: "/test-tree-cache/child1",
			data:     "child1",
		},
		{
			realPath: "/test-tree-cache/child1/child1_1",
			data:     "child1_1",
		},
		{
			realPath: "/test-tree-cache/child2",
			data:     "child2",
		},
		{
			realPath: "/test-tree-cache/child2/child2_1",
			data:     "child2_1",
		},
	}

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			for _, n := range initialNodes {
				_, err := c.Create(n.realPath, []byte(n.data), 0, WorldACL(PermAll))
				if err != nil {
					t.Fatalf("failed to create node %s: %v", n.realPath, err)
				}
			}

			cache := NewTreeCache(c, "/test-tree-cache",
				WithTreeCacheIncludeData(true))
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*500)
			defer cancel()

			syncErrCh := make(chan error, 1)

			// Start syncing cache in the background.
			go func() {
				defer close(syncErrCh)
				syncErrCh <- cache.Sync(ctx)
			}()

			// Wait for the first full sync to complete.
			err := cache.WaitForInitialSync(ctx)
			if err != nil {
				t.Fatalf("initial cache sync failed: %v", err)
			}

			// Get the root node.
			data, stat, err := cache.Get("/")
			if err != nil {
				t.Fatalf("failed to get cache node /: %v", err)
			}
			if string(data) != "root" {
				t.Fatalf("cache node / data mismatch: expected %s, got %s", "root", string(data))
			}
			if stat.NumChildren != 2 {
				t.Fatalf("cache node / numChildren mismatch: expected %d, got %d", 2, stat.NumChildren)
			}

			// Get a leaf node.
			data, stat, err = cache.Get("/child1/child1_1")
			if err != nil {
				t.Fatalf("failed to get cache node /child1/child1_1: %v", err)
			}
			if string(data) != "child1_1" {
				t.Fatalf("cache node /child1/child1_1 data mismatch: expected %s, got %s", "child1_1", string(data))
			}
			if stat.NumChildren != 0 {
				t.Fatalf("cache node /child1/child1_1 numChildren mismatch: expected %d, got %d", 0, stat.NumChildren)
			}

			// Get node that does no

			cancel()
			if err := <-syncErrCh; err != context.Canceled {
				t.Fatalf("expected context.Canceled, got %v", err)
			}

			// Existence.
			var found bool
			found, _, err = cache.Exists("/child1/child1_1")
			if err != nil {
				t.Fatalf("failed to exists cache node /child1/child1_1: %v", err)
			}
			if !found {
				t.Fatalf("cache node /child1/child1_1 not found")
			}
			found, _, err = cache.Exists("/foo")
			if err != nil {
				t.Fatalf("failed to exists /foo: %v", err)
			}
			if found {
				t.Fatalf("cache node /foo found")
			}

			// Root children.
			var children []string
			children, _, err = cache.Children("/")
			if err != nil {
				t.Fatalf("failed to get children for cache node /child1/child1_1: %v", err)
			}
			if len(children) != 2 {
				t.Fatalf("cache node / children mismatch: expected %d, got %d", 2, len(children))
			}
			sort.Strings(children) // For consistency.
			if children[0] != "child1" || children[1] != "child2" {
				t.Fatalf("cache node / children mismatch: expected %v, got %v", []string{"child1", "child2"}, children)
			}

			// Walking from root.
			var visited []string
			walker := cache.Walker("/")
			err = walker.IncludeRoot(true).
				DepthFirst().
				Walk(func(path string, stat *Stat) error {
					visited = append(visited, path)
					return nil
				})
			if err != nil {
				t.Fatalf("failed to walk: %v", err)
			}
			sort.Strings(visited) // For consistency.
			if len(visited) != 5 {
				t.Fatalf("cache walker visited mismatch: expected %d, got %d", 5, len(visited))
			}
			if visited[0] != "/" ||
				visited[1] != "/child1" ||
				visited[2] != "/child1/child1_1" ||
				visited[3] != "/child2" ||
				visited[4] != "/child2/child2_1" {
				t.Fatalf("cache walker visited mismatch: expected %v, got %v", []string{"/", "/child1", "/child1/child1_1", "/child2", "/child2/child2_1"}, visited)
			}
		})
	})
}

func TestTreeCache_OpsWithAbsolutePaths(t *testing.T) {
	initialNodes := []struct {
		realPath string
		data     string
	}{
		{
			realPath: "/test-tree-cache",
			data:     "root",
		},
		{
			realPath: "/test-tree-cache/child1",
			data:     "child1",
		},
		{
			realPath: "/test-tree-cache/child1/child1_1",
			data:     "child1_1",
		},
		{
			realPath: "/test-tree-cache/child2",
			data:     "child2",
		},
		{
			realPath: "/test-tree-cache/child2/child2_1",
			data:     "child2_1",
		},
	}

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			for _, n := range initialNodes {
				_, err := c.Create(n.realPath, []byte(n.data), 0, WorldACL(PermAll))
				if err != nil {
					t.Fatalf("failed to create node %s: %v", n.realPath, err)
				}
			}

			cache := NewTreeCache(c, "/test-tree-cache",
				WithTreeCacheIncludeData(true),
				WithTreeCacheAbsolutePaths(true))
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()

			syncErrCh := make(chan error, 1)

			// Start syncing cache in the background.
			go func() {
				defer close(syncErrCh)
				syncErrCh <- cache.Sync(ctx)
			}()

			// Wait for the first full sync to complete.
			err := cache.WaitForInitialSync(ctx)
			if err != nil {
				t.Fatalf("initial cache sync failed: %v", err)
			}

			// Get the root node.
			data, stat, err := cache.Get("/test-tree-cache")
			if err != nil {
				t.Fatalf("failed to get cache node /test-tree-cache: %v", err)
			}
			if string(data) != "root" {
				t.Fatalf("cache node /test-tree-cache data mismatch: expected %s, got %s", "root", string(data))
			}
			if stat.NumChildren != 2 {
				t.Fatalf("cache node /test-tree-cache numChildren mismatch: expected %d, got %d", 2, stat.NumChildren)
			}

			// Get a leaf node.
			data, stat, err = cache.Get("/test-tree-cache/child1/child1_1")
			if err != nil {
				t.Fatalf("failed to get cache node /test-tree-cache/child1/child1_1: %v", err)
			}
			if string(data) != "child1_1" {
				t.Fatalf("cache node /test-tree-cache/child1/child1_1 data mismatch: expected %s, got %s", "child1_1", string(data))
			}
			if stat.NumChildren != 0 {
				t.Fatalf("cache node /test-tree-cache/child1/child1_1 numChildren mismatch: expected %d, got %d", 0, stat.NumChildren)
			}

			cancel()
			if err := <-syncErrCh; err != context.Canceled {
				t.Fatalf("expected context.Canceled, got %v", err)
			}

			// Existence.
			var found bool
			found, _, err = cache.Exists("/test-tree-cache/child1/child1_1")
			if err != nil {
				t.Fatalf("failed to exists cache node /test-tree-cache/child1/child1_1: %v", err)
			}
			if !found {
				t.Fatalf("cache node /test-tree-cache/child1/child1_1 not found")
			}

			// Root children.
			var children []string
			children, _, err = cache.Children("/test-tree-cache")
			if err != nil {
				t.Fatalf("failed to fetch children for cache node /test-tree-cache/child1/child1_1: %v", err)
			}
			if len(children) != 2 {
				t.Fatalf("cache node /test-tree-cache children mismatch: expected %d, got %d", 2, len(children))
			}
			sort.Strings(children) // For consistency.
			if children[0] != "child1" || children[1] != "child2" {
				t.Fatalf("cache node /test-tree-cache/children mismatch: expected %v, got %v", []string{"child1", "child2"}, children)
			}

			// Walking from root.
			var visited []string
			walker := cache.Walker("/test-tree-cache")
			err = walker.IncludeRoot(true).
				DepthFirst().
				Walk(func(path string, stat *Stat) error {
					visited = append(visited, path)
					return nil
				})
			if err != nil {
				t.Fatalf("failed to walk: %v", err)
			}
			sort.Strings(visited) // For consistency.
			if len(visited) != 5 {
				t.Fatalf("cache walker visited mismatch: expected %d, got %d", 5, len(visited))
			}
			if visited[0] != "/test-tree-cache" ||
				visited[1] != "/test-tree-cache/child1" ||
				visited[2] != "/test-tree-cache/child1/child1_1" ||
				visited[3] != "/test-tree-cache/child2" ||
				visited[4] != "/test-tree-cache/child2/child2_1" {
				t.Fatalf("cache walker visited mismatch: expected %v, got %v", []string{"/", "/child1", "/child1/child1_1", "/child2", "/child2/child2_1"}, visited)
			}
		})
	})
}

func TestTreeCache_WatchesNodeCreate(t *testing.T) {
	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			_, err := c.Create("/test-tree-cache", nil, 0, WorldACL(PermAll))
			if err != nil {
				t.Fatalf("failed to create node %s: %v", "/test-tree-cache", err)
			}

			cache := NewTreeCache(c, "/test-tree-cache", WithTreeCacheIncludeData(true))
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()

			syncErrCh := make(chan error, 1)

			// Start syncing cache in the background.
			go func() {
				defer close(syncErrCh)
				syncErrCh <- cache.Sync(ctx)
			}()

			// Wait for the first full sync to complete.
			err = cache.WaitForInitialSync(ctx)
			if err != nil {
				t.Fatalf("initial cache sync failed: %v", err)
			}

			_, _ = c.Create("/test-tree-cache/child1", []byte("child1"), 0, WorldACL(PermAll))
			time.Sleep(time.Millisecond * 100)

			data, stat, err := cache.Get("/child1")
			if err != nil {
				t.Fatalf("failed to get cache node /child1: %v", err)
			}
			if string(data) != "child1" {
				t.Fatalf("cache node /child1 data mismatch: expected %s, got %s", "child1", string(data))
			}
			if stat.NumChildren != 0 {
				t.Fatalf("cache node /child1 numChildren mismatch: expected %d, got %d", 0, stat.NumChildren)
			}

			// Root node should report 1 child in stat.
			_, stat, err = cache.Exists("/")
			if err != nil {
				t.Fatalf("failed to get cache node /: %v", err)
			}
			if stat.NumChildren != 1 {
				t.Fatalf("cache node / numChildren mismatch: expected %d, got %d", 1, stat.NumChildren)
			}

			cancel()
			if err := <-syncErrCh; err != context.Canceled {
				t.Fatalf("expected context.Canceled, got %v", err)
			}
		})
	})
}

func TestTreeCache_WatchesNodeUpdate(t *testing.T) {
	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			_, err := c.Create("/test-tree-cache", nil, 0, WorldACL(PermAll))
			if err != nil {
				t.Fatalf("failed to create node %s: %v", "/test-tree-cache", err)
			}
			_, err = c.Create("/test-tree-cache/child1", []byte("foo"), 0, WorldACL(PermAll))
			if err != nil {
				t.Fatalf("failed to create node %s: %v", "/test-tree-cache/child1", err)
			}

			cache := NewTreeCache(c, "/test-tree-cache", WithTreeCacheIncludeData(true))
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()

			syncErrCh := make(chan error, 1)

			// Start syncing cache in the background.
			go func() {
				defer close(syncErrCh)
				syncErrCh <- cache.Sync(ctx)
			}()

			// Wait for the first full sync to complete.
			err = cache.WaitForInitialSync(ctx)
			if err != nil {
				t.Fatalf("initial cache sync failed: %v", err)
			}

			_, _ = c.Set("/test-tree-cache/child1", []byte("bar"), 0)
			time.Sleep(time.Millisecond * 100)

			data, stat, err := cache.Get("/child1")
			if err != nil {
				t.Fatalf("failed to get cache node /child1: %v", err)
			}
			if string(data) != "bar" {
				t.Fatalf("cache node /child1 data mismatch: expected %s, got %s", "bar", string(data))
			}
			if stat.NumChildren != 0 {
				t.Fatalf("cache node /child1 numChildren mismatch: expected %d, got %d", 0, stat.NumChildren)
			}

			cancel()
			if err := <-syncErrCh; err != context.Canceled {
				t.Fatalf("expected context.Canceled, got %v", err)
			}
		})
	})
}

func TestTreeCache_WatchesNodeDelete(t *testing.T) {
	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			_, err := c.Create("/test-tree-cache", nil, 0, WorldACL(PermAll))
			if err != nil {
				t.Fatalf("failed to create node %s: %v", "/test-tree-cache", err)
			}
			_, err = c.Create("/test-tree-cache/child1", []byte("foo"), 0, WorldACL(PermAll))
			if err != nil {
				t.Fatalf("failed to create node %s: %v", "/test-tree-cache/child1", err)
			}

			cache := NewTreeCache(c, "/test-tree-cache", WithTreeCacheIncludeData(true))
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()

			syncErrCh := make(chan error, 1)

			// Start syncing cache in the background.
			go func() {
				defer close(syncErrCh)
				syncErrCh <- cache.Sync(ctx)
			}()

			// Wait for the first full sync to complete.
			err = cache.WaitForInitialSync(ctx)
			if err != nil {
				t.Fatalf("initial cache sync failed: %v", err)
			}

			_ = c.Delete("/test-tree-cache/child1", -1)
			time.Sleep(time.Millisecond * 100)

			ok, _, err := cache.Exists("/child1")
			if err != nil {
				t.Fatalf("failed to get cache node /child1: %v", err)
			}
			if ok {
				t.Fatalf("cache node /child1 should not exist")
			}

			cancel()
			if err := <-syncErrCh; err != context.Canceled {
				t.Fatalf("expected context.Canceled, got %v", err)
			}
		})
	})
}

func TestTreeCache_RecoversFromDisconnect(t *testing.T) {
	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c1 *Conn, ech1 <-chan Event) {
			c1.reconnectLatch = make(chan struct{})

			_, err := c1.Create("/test-tree-cache", nil, 0, WorldACL(PermAll))
			if err != nil {
				t.Fatalf("failed to create node %s: %v", "/test-tree-cache", err)
			}

			syncDoneChan := make(chan struct{}, 1)

			cache := NewTreeCache(c1, "/test-tree-cache",
				WithTreeCacheIncludeData(true),
				WithTreeCacheListener(&TreeCacheListenerFuncs{
					OnSyncStoppedFunc: func() { close(syncDoneChan) },
					OnTreeSyncedFunc:  func() { syncDoneChan <- struct{}{} },
				}))
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()

			syncErrCh := make(chan error, 1)

			// Start syncing cache in the background.
			go func() {
				defer close(syncErrCh)
				syncErrCh <- cache.Sync(ctx)
			}()

			// Wait for the first full sync to complete.
			err = cache.WaitForInitialSync(ctx)
			if err != nil {
				t.Fatalf("initial cache sync failed: %v", err)
			}

			// Eat the first item from syncDoneChan (initial sync).
			select {
			case <-syncDoneChan:
			default:
			}

			// Simulate network error by brutally closing the network connection.
			_ = c1.conn.Close()
			// Reconnection will be blocked by the latch.

			// While c1 is disconnected, create a bunch of nodes on a new connection.
			// This will cause the cache to miss some events, but hopefully it will catch up on session reestablishment.
			WithConnectAll(t, tc, func(t *testing.T, c2 *Conn, _ <-chan Event) {
				for i := 0; i < 100; i++ {
					_, err := c2.Create("/test-tree-cache/child-"+strconv.Itoa(i), []byte("foo"), 0, WorldACL(PermAll))
					if err != nil {
						t.Fatalf("failed to create node %s: %v", "/test-tree-cache/child-"+strconv.Itoa(i), err)
					}
				}
			})

			close(c1.reconnectLatch) // Unblock reconnection.

			// Wait for second item from syncDoneChan (sync after reconnection).
			select {
			case <-syncDoneChan:
			case <-ctx.Done():
				t.Fatalf("failed to wait for syncDoneChan: %v", ctx.Err())
			}

			// Check that all nodes are present in the cache.
			for i := 0; i < 100; i++ {
				ok, _, err := cache.Exists("/child-" + strconv.Itoa(i))
				if err != nil {
					t.Fatalf("failed to get cache node /child-%d: %v", i, err)
				}
				if !ok {
					t.Fatalf("cache node /child-%d should exist", i)
				}
			}

			cancel()
			if err := <-syncErrCh; err != context.Canceled {
				t.Fatalf("expected context.Canceled, got %v", err)
			}
		})
	})
}
