package zk

import (
	"context"
	"fmt"
	"io/ioutil"
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
		logger:         DefaultLogger,
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
	cases := []struct {
		eType   EventType
		path    string
		watches map[watchPathType]bool
	}{
		{
			EventNodeCreated, "/",
			map[watchPathType]bool{
				{"/", watchTypeExist}: true,
				{"/", watchTypeChild}: false,
				{"/", watchTypeData}:  false,
			},
		},
		{
			EventNodeCreated, "/a",
			map[watchPathType]bool{
				{"/b", watchTypeExist}: false,
			},
		},
		{
			EventNodeDataChanged, "/",
			map[watchPathType]bool{
				{"/", watchTypeExist}: true,
				{"/", watchTypeData}:  true,
				{"/", watchTypeChild}: false,
			},
		},
		{
			EventNodeChildrenChanged, "/",
			map[watchPathType]bool{
				{"/", watchTypeExist}: false,
				{"/", watchTypeData}:  false,
				{"/", watchTypeChild}: true,
			},
		},
		{
			EventNodeDeleted, "/",
			map[watchPathType]bool{
				{"/", watchTypeExist}: true,
				{"/", watchTypeData}:  true,
				{"/", watchTypeChild}: true,
			},
		},
	}

	conn := &Conn{watchers: make(map[watchPathType][]chan Event)}

	for idx, c := range cases {
		t.Run(fmt.Sprintf("#%d %s", idx, c.eType), func(t *testing.T) {
			c := c

			notifications := make([]struct {
				path   string
				notify bool
				ch     <-chan Event
			}, len(c.watches))

			var idx int
			for wpt, expectEvent := range c.watches {
				ch := conn.addWatcher(wpt.path, wpt.wType)
				notifications[idx].path = wpt.path
				notifications[idx].notify = expectEvent
				notifications[idx].ch = ch
				idx++
			}
			ev := Event{Type: c.eType, Path: c.path}
			conn.notifyWatches(ev)

			for _, res := range notifications {
				select {
				case e := <-res.ch:
					if !res.notify || e.Path != res.path {
						t.Fatal("unexpeted notification received")
					}
				default:
					if res.notify {
						t.Fatal("expected notification not received")
					}
				}
			}
		})
	}
}
