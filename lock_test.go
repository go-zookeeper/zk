package zk

import (
	"context"
	"testing"
	"time"
)

func TestLock(t *testing.T) {
	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, ech <-chan Event) {
			acls := WorldACL(PermAll)

			l := NewLock(c, "/test", acls)
			if err := l.Lock(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := l.Unlock(context.Background()); err != nil {
				t.Fatal(err)
			}

			val := make(chan int, 3)

			if err := l.Lock(context.Background()); err != nil {
				t.Fatal(err)
			}

			l2 := NewLock(c, "/test", acls)
			l2Errs := make(chan error, 2)
			go func() {
				defer close(l2Errs)
				if err := l2.Lock(context.Background()); err != nil {
					l2Errs <- err
					return
				}
				val <- 2
				if err := l2.Unlock(context.Background()); err != nil {
					l2Errs <- err
					return
				}
				val <- 3
			}()
			time.Sleep(time.Millisecond * 100)

			val <- 1
			if err := l.Unlock(context.Background()); err != nil {
				t.Fatal(err)
			}
			if x := <-val; x != 1 {
				t.Fatalf("Expected 1 instead of %d", x)
			}
			if x := <-val; x != 2 {
				t.Fatalf("Expected 2 instead of %d", x)
			}
			if x := <-val; x != 3 {
				t.Fatalf("Expected 3 instead of %d", x)
			}

			if e, ok := <-l2Errs; ok {
				t.Fatal(e)
			}
		})
	})
}

// This tests creating a lock with a path that's more than 1 node deep (e.g. "/test-multi-level/lock"),
// when a part of that path already exists (i.e. "/test-multi-level" node already exists).
func TestMultiLevelLock(t *testing.T) {
	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, ech <-chan Event) {
			acls := WorldACL(PermAll)
			path := "/test-multi-level"

			if p, err := c.Create(context.Background(), path, []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			} else if p != path {
				t.Fatalf("Create returned different path '%s' != '%s'", p, path)
			}

			l := NewLock(c, "/test-multi-level/lock", acls)

			// Clean up what we've created for this test
			defer c.Delete(context.Background(), "/test-multi-level", -1)      // nolint: errcheck
			defer c.Delete(context.Background(), "/test-multi-level/lock", -1) // nolint: errcheck

			if err := l.Lock(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := l.Unlock(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	})
}

func TestParseSeq(t *testing.T) {
	const (
		goLock       = "_c_38553bd6d1d57f710ae70ddcc3d24715-lock-0000000000"
		negativeLock = "_c_38553bd6d1d57f710ae70ddcc3d24715-lock--2147483648"
		pyLock       = "da5719988c244fc793f49ec3aa29b566__lock__0000000003"
	)

	seq, err := parseSeq(goLock)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 0 {
		t.Fatalf("Expected 0 instead of %d", seq)
	}

	seq, err = parseSeq(negativeLock)
	if err != nil {
		t.Fatal(err)
	}
	if seq != -2147483648 {
		t.Fatalf("Expected -2147483648 instead of %d", seq)
	}

	seq, err = parseSeq(pyLock)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 3 {
		t.Fatalf("Expected 3 instead of %d", seq)
	}
}
