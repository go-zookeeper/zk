package zk

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	// ErrDeadlock is returned by Lock when trying to lock twice without unlocking first
	ErrDeadlock = errors.New("zk: trying to acquire a lock twice")
	// ErrNotLocked is returned by Unlock when trying to release a lock that has not first be acquired.
	ErrNotLocked = errors.New("zk: not locked")
)

// Lock is a mutual exclusion lock.
type Lock struct {
	c        *Conn
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
	parts := strings.Split(path, "lock-")
	// python client uses a __LOCK__ prefix
	if len(parts) == 1 {
		parts = strings.Split(path, "__")
	}
	return strconv.Atoi(parts[len(parts)-1])
}

// Lock attempts to acquire the lock. It works like LockWithData, but it doesn't
// write any data to the lock node.
func (l *Lock) Lock(ctx context.Context) error {
	return l.LockWithData(ctx, []byte{})
}

// LockWithData attempts to acquire the lock, writing data into the lock node.
// It will wait to return until the lock is acquired or an error occurs. If
// this instance already has the lock then ErrDeadlock is returned.
func (l *Lock) LockWithData(ctx context.Context, data []byte) error {
	if l.lockPath != "" {
		return ErrDeadlock
	}

	prefix := fmt.Sprintf("%s/lock-", l.path)
	path := ""

	var err error
	for range 3 {
		path, err = l.c.CreateProtectedEphemeralSequential(ctx, prefix, data, l.acl)
		if errors.Is(err, ErrNoNode) {
			// Create parent node.
			parts := strings.Split(l.path, "/")
			var pth strings.Builder
			for _, p := range parts[1:] {
				var exists bool
				pth.WriteString("/" + p)
				exists, _, err = l.c.Exists(ctx, pth.String())
				if err != nil {
					return err
				}
				if exists {
					continue
				}
				_, err = l.c.Create(ctx, pth.String(), []byte{}, 0, l.acl)
				if err != nil && !errors.Is(err, ErrNodeExists) {
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

	acquired := false
	defer func() {
		if !acquired {
			// Cleanup our ephemeral node, if we return before acquiring the lock.
			// Otherwise, we risk leaking the lock and blocking other participants.
			_ = l.c.Delete(ctx, path, -1)
		}
	}()

	for {
		children, _, err := l.c.Children(ctx, l.path)
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
			acquired = true
			break
		}

		// Wait on the node next in line for the lock
		_, _, ch, err := l.c.GetW(ctx, l.path+"/"+prevSeqPath)
		if err != nil && !errors.Is(err, ErrNoNode) {
			return err
		} else if errors.Is(err, ErrNoNode) {
			// try again
			continue
		}

		select {
		case ev := <-ch:
			if ev.Err != nil {
				return ev.Err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	l.seq = seq
	l.lockPath = path
	return nil
}

// Unlock releases an acquired lock. If the lock is not currently acquired by
// this Lock instance than ErrNotLocked is returned.
func (l *Lock) Unlock(ctx context.Context) error {
	if l.lockPath == "" {
		return ErrNotLocked
	}
	if err := l.c.Delete(ctx, l.lockPath, -1); err != nil {
		return err
	}
	l.lockPath = ""
	l.seq = 0
	return nil
}
