package zk

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
)

var (
	// ErrDeadlock is returned by Lock when trying to lock twice without unlocking first
	ErrDeadlock = errors.New("zk: trying to acquire a lock twice")
	// ErrNotLocked is returned by Unlock when trying to release a lock that has not first be acquired.
	ErrNotLocked = errors.New("zk: not locked")
	// ErrAcquireLockTimeout is returned by Lock when occur timeout.
	ErrAcquireLockTimeout = errors.New("zk: timeout to acquire a lock")
)

const (
	lockStateNone int32 = iota
	lockStateAcquiring
	lockStateAcquired
	lockStateLeasing
)

// Lock is a mutual exclusion lock.
type Lock struct {
	c        *Conn
	state    int32
	path     string
	acl      []ACL
	lockPath string
	seq      int
}

// NewLock creates a new lock instance using the provided connection, path, and acl.
// The path must be a node that is only used by this lock. A lock instances starts
// unlocked until Lock() is called.
func NewLock(c *Conn, path string, acl []ACL) *Lock {
	return &Lock{
		c:    c,
		path: path,
		acl:  acl,
	}
}

func parseSeq(path string) (int, error) {
	parts := strings.Split(path, "-")
	// python client uses a __LOCK__ prefix
	if len(parts) == 1 {
		parts = strings.Split(path, "__")
	}
	return strconv.Atoi(parts[len(parts)-1])
}

// Lock attempts to acquire the lock. It works like LockWithData, but it doesn't
// write any data to the lock node.
func (l *Lock) Lock() error {
	return l.LockContextWithData(context.Background(), []byte{})
}

// LockContext attempts to acquire the lock with the given context. It works like LockContextWithData, but it doesn't
// write any data to the lock node.
func (l *Lock) LockContext(ctx context.Context) error {
	return l.LockContextWithData(ctx, []byte{})
}

// LockWithData attempts to acquire the lock, writing data into the lock node.
// It will wait to return until the lock is acquired or an error occurs. If
// this instance already has the lock then ErrDeadlock is returned.
func (l *Lock) LockWithData(data []byte) error {
	return l.LockContextWithData(context.Background(), data)
}

// LockContextWithData attempts to acquire the lock, writing data into the lock node.
// It will wait to return until the lock is acquired or an error occurs, the context is done. If
// this instance already has the lock then ErrDeadlock is returned.
// ErrAcquireLockTimeout will also be returned if the given context is done.
func (l *Lock) LockContextWithData(ctx context.Context, data []byte) error {
	if !atomic.CompareAndSwapInt32(&l.state, lockStateNone, lockStateAcquiring) {
		return ErrDeadlock
	}
	if err := l.lockWithData(ctx, data); err != nil {
		atomic.StoreInt32(&l.state, lockStateNone)
		return err
	}
	atomic.StoreInt32(&l.state, lockStateAcquired)
	return nil
}

func (l *Lock) lockWithData(ctx context.Context, data []byte) error {
	prefix := fmt.Sprintf("%s/lock-", l.path)

	path := ""
	var err error
	for i := 0; i < 3; i++ {
		if isContextDone(ctx) {
			return ErrAcquireLockTimeout
		}
		path, err = l.c.CreateProtectedEphemeralSequential(prefix, data, l.acl)
		if err == ErrNoNode {
			// Create parent node.
			parts := strings.Split(l.path, "/")
			pth := ""
			for _, p := range parts[1:] {
				var exists bool
				pth += "/" + p
				exists, _, err = l.c.Exists(pth)
				if err != nil {
					return err
				}
				if exists == true {
					continue
				}
				_, err = l.c.Create(pth, []byte{}, 0, l.acl)
				if err != nil && err != ErrNodeExists {
					return err
				}
			}
		} else if err == nil {
			break
		} else {
			return err
		}
	}
	if err != nil {
		return err
	}

	seq, err := parseSeq(path)
	if err != nil {
		return err
	}

	for {
		children, _, err := l.c.Children(l.path)
		if err != nil {
			return err
		}

		lowestSeq := seq
		prevSeq := -1
		prevSeqPath := ""
		for _, p := range children {
			s, err := parseSeq(p)
			if err != nil {
				return err
			}
			if s < lowestSeq {
				lowestSeq = s
			}
			if s < seq && s > prevSeq {
				prevSeq = s
				prevSeqPath = p
			}
		}

		if seq == lowestSeq {
			// Acquired the lock
			break
		}

		// Wait on the node next in line for the lock
		_, _, ch, err := l.c.GetW(l.path + "/" + prevSeqPath)
		if err != nil && err != ErrNoNode {
			return err
		} else if err != nil && err == ErrNoNode {
			// try again
			continue
		}

		select {
		case ev := <-ch:
			if ev.Err != nil {
				if err := l.c.Delete(path, -1); err != nil {
					return err
				}
				return ev.Err
			}
		case <-ctx.Done():
			if err := l.c.Delete(path, -1); err != nil {
				return err
			}
			return ErrAcquireLockTimeout
		}
	}
	if isContextDone(ctx) {
		if err := l.c.Delete(path, -1); err != nil {
			return err
		}
		return ErrAcquireLockTimeout
	}

	l.seq = seq
	l.lockPath = path
	return nil
}

// Unlock releases an acquired lock. If the lock is not currently acquired by
// this Lock instance than ErrNotLocked is returned.
func (l *Lock) Unlock() error {
	if !atomic.CompareAndSwapInt32(&l.state, lockStateAcquired, lockStateLeasing) {
		return ErrNotLocked
	}
	if err := l.c.Delete(l.lockPath, -1); err != nil {
		if err == ErrNoNode {
			atomic.StoreInt32(&l.state, lockStateNone)
			return ErrNotLocked
		}
		return err
	}
	l.lockPath = ""
	l.seq = 0
	atomic.StoreInt32(&l.state, lockStateNone)
	return nil
}

func isContextDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
