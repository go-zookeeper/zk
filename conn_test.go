package zk

import (
	"context"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIntegration_RecurringReAuthHang(t *testing.T) {
	zkC, err := StartTestCluster(t, 3, ioutil.Discard, ioutil.Discard)
	if err != nil {
		panic(err)
	}
	defer zkC.Stop()

	conn, evtC, err := zkC.ConnectAll()
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	waitForSession(ctx, evtC)
	// Add auth.
	conn.AddAuth("digest", []byte("test:test"))

	var reauthCloseOnce sync.Once
	reauthSig := make(chan struct{}, 1)
	conn.resendZkAuthFn = func(ctx context.Context, c *Conn) error {
		// in current implimentation the reauth might be called more than once based on various conditions
		reauthCloseOnce.Do(func() { close(reauthSig) })
		return resendZkAuth(ctx, c)
	}

	conn.debugCloseRecvLoop = true
	currentServer := conn.Server()
	zkC.StopServer(currentServer)
	// wait connect to new zookeeper.
	ctx, cancel = context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	waitForSession(ctx, evtC)

	select {
	case _, ok := <-reauthSig:
		if !ok {
			return // we closed the channel as expected
		}
		t.Fatal("reauth testing channel should have been closed")
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestConcurrentReadAndClose(t *testing.T) {
	WithListenServer(t, func(server string) {
		conn, _, err := Connect([]string{server}, 15*time.Second)
		if err != nil {
			t.Fatalf("Failed to create Connection %s", err)
		}

		okChan := make(chan struct{})
		var setErr error
		go func() {
			_, setErr = conn.Create("/test-path", []byte("test data"), 0, WorldACL(PermAll))
			close(okChan)
		}()

		go func() {
			time.Sleep(1 * time.Second)
			conn.Close()
		}()

		select {
		case <-okChan:
			if setErr != ErrConnectionClosed {
				t.Fatalf("unexpected error returned from Set %v", setErr)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("apparent deadlock!")
		}
	})
}

func TestDeadlockInClose(t *testing.T) {
	c := &Conn{
		shouldQuit:     make(chan struct{}),
		connectTimeout: 1 * time.Second,
		sendChan:       make(chan *request, sendChanSize),
	}

	for i := 0; i < sendChanSize; i++ {
		c.sendChan <- &request{}
	}

	okChan := make(chan struct{})
	go func() {
		c.Close()
		close(okChan)
	}()

	select {
	case <-okChan:
	case <-time.After(3 * time.Second):
		t.Fatal("apparent deadlock!")
	}
}

func TestNotifyWatches(t *testing.T) {
	queueImpls := []struct {
		name string
		new  func() EventQueue
	}{
		{
			name: "chan",
			new:  func() EventQueue { return newChanEventChannel() },
		},
		{
			name: "unlimited",
			new:  func() EventQueue { return NewUnlimitedQueue[Event]() },
		},
	}

	cases := []struct {
		eType   EventType
		path    string
		watches map[watchPathType]bool
	}{
		{
			eType: EventNodeCreated,
			path:  "/a",
			watches: map[watchPathType]bool{
				{"/a", watchTypeExist}: true,
				{"/b", watchTypeExist}: false,

				{"/a", watchTypeChild}: false,

				{"/a", watchTypeData}: false,

				{"/a", watchTypePersistent}: true,
				{"/", watchTypePersistent}:  false,

				{"/a", watchTypePersistentRecursive}: true,
				{"/", watchTypePersistentRecursive}:  true,
			},
		},
		{
			eType: EventNodeDataChanged,
			path:  "/a",
			watches: map[watchPathType]bool{
				{"/a", watchTypeExist}: true,
				{"/a", watchTypeData}:  true,
				{"/a", watchTypeChild}: false,

				{"/a", watchTypePersistent}: true,
				{"/", watchTypePersistent}:  false,

				{"/a", watchTypePersistentRecursive}: true,
				{"/", watchTypePersistentRecursive}:  true,
			},
		},
		{
			eType: EventNodeChildrenChanged,
			path:  "/a",
			watches: map[watchPathType]bool{
				{"/a", watchTypeExist}:               false,
				{"/a", watchTypeData}:                false,
				{"/a", watchTypeChild}:               true,
				{"/a", watchTypePersistent}:          true,
				{"/a", watchTypePersistentRecursive}: false,

				{"/a", watchTypePersistent}: true,
				{"/", watchTypePersistent}:  false,

				{"/a", watchTypePersistentRecursive}: false,
				{"/", watchTypePersistentRecursive}:  false,
			},
		},
		{
			eType: EventNodeDeleted,
			path:  "/a",
			watches: map[watchPathType]bool{
				{"/a", watchTypeExist}: true,
				{"/a", watchTypeData}:  true,
				{"/a", watchTypeChild}: true,

				{"/a", watchTypePersistent}: true,
				{"/", watchTypePersistent}:  false,

				{"/a", watchTypePersistentRecursive}: true,
				{"/", watchTypePersistentRecursive}:  true,
			},
		},
	}

	for _, impl := range queueImpls {
		t.Run(impl.name, func(t *testing.T) {
			for idx, c := range cases {
				c := c
				t.Run(fmt.Sprintf("#%d %s", idx, c.eType), func(t *testing.T) {
					notifications := make([]struct {
						watchPathType
						notify bool
						ch     EventQueue
					}, len(c.watches))

					conn := &Conn{watchers: make(map[watchPathType][]EventQueue)}

					var idx int
					for wpt, expectEvent := range c.watches {
						notifications[idx].watchPathType = wpt
						notifications[idx].notify = expectEvent
						ch := impl.new()
						conn.addWatcher(wpt.path, wpt.wType, ch)
						notifications[idx].ch = ch
						if wpt.wType.isPersistent() {
							e, _ := ch.Next(context.Background())
							if e.Type != EventWatching {
								t.Fatalf("First event on persistent watcher should always be EventWatching")
							}
						}
						idx++
					}

					conn.notifyWatches(Event{Type: c.eType, Path: c.path})

					for _, res := range notifications {
						ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
						t.Cleanup(cancel)

						e, err := res.ch.Next(ctx)
						if err == nil {
							isPathCorrect :=
								(res.wType == watchTypePersistentRecursive && strings.HasPrefix(e.Path, res.path)) ||
									e.Path == res.path
							if !res.notify || !isPathCorrect {
								t.Logf("unexpeted notification received by %+v: %+v", res, e)
								t.Fail()
							}
						} else {
							if res.notify {
								t.Logf("expected notification not received for %+v", res)
								t.Fail()
							}
						}
					}
				})
			}
		})
	}
}
