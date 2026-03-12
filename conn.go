// Package zk is a native Go client library for the ZooKeeper orchestration service.
package zk

/*
TODO:
* make sure a ping response comes back in a reasonable time

Possible watcher events:
* Event{Type: EventNotWatching, State: StateDisconnected, Path: path, Err: err}
*/

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ErrNoServer indicates that an operation cannot be completed
// because attempts to connect to all servers in the list failed.
var ErrNoServer = errors.New("zk: could not connect to a server")

// ErrInvalidPath indicates that an operation was being attempted on
// an invalid path. (e.g. empty path).
var ErrInvalidPath = errors.New("zk: invalid path")

const (
	bufferSize      = 1536 * 1024
	eventChanSize   = 6
	sendChanSize    = 16
	protectedPrefix = "_c_"
)

// Dialer is a function to be used to establish a connection to a single host.
type Dialer func(network, address string, timeout time.Duration) (net.Conn, error)

type authCreds struct {
	scheme string
	auth   []byte
}

// Conn is the client connection and tracks all details for communication with the server.
type Conn struct {
	lastZxid         int64
	sessionID        atomic.Int64
	state            atomic.Int32
	xid              atomic.Uint32
	sessionTimeoutMs int32 // session timeout in milliseconds
	passwd           []byte

	dialer         Dialer
	hostProvider   HostProvider
	serverMu       sync.Mutex // protects server
	server         string     // remember the address/port of the current server
	conn           net.Conn
	eventChan      chan Event
	eventCallback  EventCallback // may be nil
	shouldQuit     chan struct{}
	closeFn        func()
	pingInterval   time.Duration
	ioTimeout      time.Duration
	connectTimeout time.Duration
	maxBufferSize  int

	creds   []authCreds
	credsMu sync.Mutex // protects server

	sendChan      chan *request
	requests      map[int32]*request // Xid -> pending request
	requestsLock  sync.Mutex
	watchersByKey map[watcherKey][]watcher
	watchersLock  sync.Mutex
	closeChan     chan struct{} // channel to tell send loop stop

	// Debug (used by unit tests)
	reconnectLatch   chan struct{}
	setWatchLimit    int
	setWatchCallback func([]*setWatches2Request)

	// Debug (for recurring re-auth hang)
	debugCloseRecvLoop bool
	resendZkAuthFn     func(context.Context, *Conn) error

	logger  *slog.Logger
	logInfo bool // true if information messages are logged; false if only errors are logged

	buf []byte
}

// connOption represents a connection option.
type connOption func(c *Conn)

type request struct {
	xid        int32
	opcode     int32
	pkt        any
	recvStruct any
	recvChan   chan response

	// Because sending and receiving happen in separate go routines, there's
	// a possible race condition when creating watches from outside the read
	// loop. We must ensure that a watcher gets added to the list synchronously
	// with the response from the server on any request that creates a watch.
	// In order to not hard code the watch logic for each opcode in the recv
	// loop the caller can use recvFunc to insert some synchronously code
	// after a response.
	recvFunc func(*request, *responseHeader, error)
}

type response struct {
	zxid int64
	err  error
}

// Event is an Znode event sent by the server.
// Refer to EventType for more details.
type Event struct {
	Type   EventType
	State  State
	Path   string // For non-session events, the path of the watched node.
	Err    error
	Server string // For connection events
}

// HostProvider is used to represent a set of hosts a ZooKeeper client should connect to.
// It is an analog of the Java equivalent:
// http://svn.apache.org/viewvc/zookeeper/trunk/src/java/main/org/apache/zookeeper/client/HostProvider.java?view=markup
type HostProvider interface {
	// Init is called first, with the servers specified in the connection string.
	Init(servers []string) error
	// Len returns the number of servers.
	Len() int
	// Next returns the next server to connect to. retryStart will be true if we've looped through
	// all known servers without Connected() being called.
	Next() (server string, retryStart bool)
	// Notify the HostProvider of a successful connection.
	Connected()
}

// Connect establishes a new connection to a pool of zookeeper
// servers. The provided session timeout sets the amount of time for which
// a session is considered valid after losing connection to a server. Within
// the session timeout it's possible to reestablish a connection to a different
// server and keep the same session. This is means any ephemeral nodes and
// watches are maintained.
func Connect(servers []string, sessionTimeout time.Duration, options ...connOption) (*Conn, <-chan Event, error) {
	if len(servers) == 0 {
		return nil, nil, errors.New("zk: server list must not be empty")
	}

	srvs := FormatServers(servers)

	// Randomize the order of the servers to avoid creating hotspots
	stringShuffle(srvs)

	ec := make(chan Event, eventChanSize)
	conn := &Conn{
		dialer:         net.DialTimeout,
		hostProvider:   &DNSHostProvider{},
		conn:           nil,
		eventChan:      ec,
		shouldQuit:     make(chan struct{}),
		connectTimeout: 1 * time.Second,
		sendChan:       make(chan *request, sendChanSize),
		requests:       make(map[int32]*request),
		watchersByKey:  make(map[watcherKey][]watcher),
		passwd:         emptyPassword,
		logger:         slog.Default(),
		logInfo:        true, // default is true for backwards compatability
		buf:            make([]byte, bufferSize),
		resendZkAuthFn: resendZkAuth,
	}

	conn.state.Store(int32(StateDisconnected))
	conn.closeFn = sync.OnceFunc(func() {
		close(conn.shouldQuit)
		select {
		case <-conn.queueRequest(context.Background(), opClose, nil, nil, nil):
		case <-time.After(time.Second):
		}
	})

	// Set provided options.
	for _, option := range options {
		option(conn)
	}

	if err := conn.hostProvider.Init(srvs); err != nil {
		return nil, nil, err
	}

	conn.setTimeouts(int32(sessionTimeout / time.Millisecond))
	ctx := context.Background()

	go func() {
		conn.loop(ctx)
		conn.flushRequests(ErrClosing)
		conn.invalidateWatchers(ErrClosing)
		close(conn.eventChan)
	}()

	return conn, ec, nil
}

// WithDialer returns a connection option specifying a non-default Dialer.
func WithDialer(dialer Dialer) connOption { // nolint:revive
	return func(c *Conn) {
		c.dialer = dialer
	}
}

// WithHostProvider returns a connection option specifying a non-default HostProvider.
func WithHostProvider(hostProvider HostProvider) connOption { // nolint:revive
	return func(c *Conn) {
		c.hostProvider = hostProvider
	}
}

// WithLogger returns a connection option specifying a non-default slog Logger.
func WithLogger(logger *slog.Logger) connOption { // nolint: revive
	return func(c *Conn) {
		c.logger = logger
	}
}

// WithLogInfo returns a connection option specifying whether or not information messages
// should be logged.
func WithLogInfo(logInfo bool) connOption { // nolint: revive
	return func(c *Conn) {
		c.logInfo = logInfo
	}
}

// EventCallback is a function that is called when an Event occurs.
type EventCallback func(Event)

// WithEventCallback returns a connection option that specifies an event
// callback.
// The callback must not block - doing so would delay the ZK go routines.
func WithEventCallback(cb EventCallback) connOption { // nolint: revive
	return func(c *Conn) {
		c.eventCallback = cb
	}
}

// WithMaxBufferSize sets the maximum buffer size used to read and decode
// packets received from the Zookeeper server. The standard Zookeeper client for
// Java defaults to a limit of 1mb. For backwards compatibility, this Go client
// defaults to unbounded unless overridden via this option. A value that is zero
// or negative indicates that no limit is enforced.
//
// This is meant to prevent resource exhaustion in the face of potentially
// malicious data in ZK. It should generally match the server setting (which
// also defaults ot 1mb) so that clients and servers agree on the limits for
// things like the size of data in an individual znode and the total size of a
// transaction.
//
// For production systems, this should be set to a reasonable value (ideally
// that matches the server configuration). For ops tooling, it is handy to use a
// much larger limit, in order to do things like clean-up problematic state in
// the ZK tree. For example, if a single znode has a huge number of children, it
// is possible for the response to a "list children" operation to exceed this
// buffer size and cause errors in clients. The only way to subsequently clean
// up the tree (by removing superfluous children) is to use a client configured
// with a larger buffer size that can successfully query for all of the child
// names and then remove them. (Note there are other tools that can list all of
// the child names without an increased buffer size in the client, but they work
// by inspecting the servers' transaction logs to enumerate children instead of
// sending an online request to a server.
func WithMaxBufferSize(maxBufferSize int) connOption { // nolint: revive
	return func(c *Conn) {
		c.maxBufferSize = maxBufferSize
	}
}

// WithMaxConnBufferSize sets maximum buffer size used to send and encode
// packets to Zookeeper server. The standard Zookeeper client for java defaults
// to a limit of 1mb. This option should be used for non-standard server setup
// where znode is bigger than default 1mb.
func WithMaxConnBufferSize(maxBufferSize int) connOption { // nolint: revive
	return func(c *Conn) {
		c.buf = make([]byte, maxBufferSize)
	}
}

// Close will submit a close request with ZK and signal the connection to stop sending and receiving packets.
func (c *Conn) Close() {
	c.closeFn()
}

// State returns the current state of the connection.
func (c *Conn) State() State {
	return State(c.state.Load())
}

// SessionID returns the current session id of the connection.
func (c *Conn) SessionID() int64 {
	return c.sessionID.Load()
}

// SetLogger sets the logger to be used for printing errors.
func (c *Conn) SetLogger(l *slog.Logger) {
	c.logger = l
}

func (c *Conn) setTimeouts(sessionTimeoutMs int32) {
	c.sessionTimeoutMs = sessionTimeoutMs
	sessionTimeout := time.Duration(sessionTimeoutMs) * time.Millisecond
	c.ioTimeout = sessionTimeout * 2 / 3
	c.pingInterval = c.ioTimeout / 2
}

func (c *Conn) setState(state State) {
	c.state.Store(int32(state))
	c.sendEvent(Event{Type: EventSession, State: state, Server: c.Server()})
}

func (c *Conn) sendEvent(evt Event) {
	if c.eventCallback != nil {
		c.eventCallback(evt)
	}

	select {
	case c.eventChan <- evt:
	default:
		// panic("zk: event channel full - it must be monitored and never allowed to be full")
	}
}

func (c *Conn) connect() error {
	var retryStart bool
	for {
		c.serverMu.Lock()
		c.server, retryStart = c.hostProvider.Next()
		c.serverMu.Unlock()

		c.setState(StateConnecting)

		if retryStart {
			c.flushUnsentRequests(ErrNoServer)
			select {
			case <-time.After(time.Second):
				// pass
			case <-c.shouldQuit:
				c.setState(StateDisconnected)
				c.flushUnsentRequests(ErrClosing)
				return ErrClosing
			}
		}

		zkConn, err := c.dialer("tcp", c.Server(), c.connectTimeout)
		if err == nil {
			c.conn = zkConn
			c.setState(StateConnected)
			if c.logInfo {
				c.logger.Info("connected", "server", c.Server())
			}
			return nil
		}

		c.logger.Error("failed to connect", "server", c.Server(), "error", err)
	}
}

func (c *Conn) sendRequest(
	opcode int32,
	req any,
	res any,
	recvFunc func(*request, *responseHeader, error),
) (
	<-chan response,
	error,
) {
	rq := &request{
		xid:        c.nextXid(),
		opcode:     opcode,
		pkt:        req,
		recvStruct: res,
		recvChan:   make(chan response, 1),
		recvFunc:   recvFunc,
	}

	if err := c.sendData(rq); err != nil {
		return nil, err
	}

	return rq.recvChan, nil
}

func (c *Conn) sessionExpired(d time.Time) bool {
	return d.Add(time.Duration(c.sessionTimeoutMs) * time.Millisecond).Before(time.Now())
}

func (c *Conn) loop(ctx context.Context) {
	var disconnectTime time.Time
	for {
		if err := c.connect(); err != nil {
			// c.Close() was called
			return
		}

		err := c.authenticate()
		switch {
		case errors.Is(err, ErrSessionExpired):
			c.logger.Error("authentication expired", "error", err)
			c.resetSession(err)
		case err != nil && c.conn != nil:
			c.logger.Error("authentication failed", "error", err)
			c.conn.Close()
			if !disconnectTime.IsZero() && c.sessionExpired(disconnectTime) {
				c.resetSession(ErrSessionExpired)
			}
		case err == nil:
			if c.logInfo {
				c.logger.Info("authenticated", "id", c.SessionID(), "timeout", c.sessionTimeoutMs)
			}
			c.hostProvider.Connected()        // mark success
			c.closeChan = make(chan struct{}) // channel to tell send loop stop

			var wg sync.WaitGroup

			wg.Go(func() {
				defer c.conn.Close() // causes recv loop to EOF/exit

				if err := c.resendZkAuthFn(ctx, c); err != nil {
					c.logger.Error("error in resending auth creds", "error", err)
					return
				}

				if err := c.sendLoop(); err != nil || c.logInfo {
					c.logger.Info("send loop terminated", "error", err)
				}
			})

			wg.Go(func() {
				defer close(c.closeChan) // tell send loop to exit

				var err error
				if c.debugCloseRecvLoop {
					err = errors.New("DEBUG: close recv loop")
				} else {
					err = c.recvLoop(c.conn)
				}
				if !errors.Is(err, io.EOF) || c.logInfo {
					c.logger.Info("recv loop terminated", "error", err)
				}
				if err == nil {
					panic("zk: recvLoop should never return nil error")
				}
			})

			c.restoreWatches()
			wg.Wait()
		}

		disconnectTime = time.Now()
		c.setState(StateDisconnected)
		c.invalidateWatchersOnDisconnect()

		select {
		case <-c.shouldQuit:
			c.flushRequests(ErrClosing)
			return
		default:
		}

		if !errors.Is(err, ErrSessionExpired) {
			err = ErrConnectionClosed
		}
		c.flushRequests(err)

		if c.reconnectLatch != nil {
			select {
			case <-c.shouldQuit:
				return
			case <-c.reconnectLatch:
			}
		}
	}
}

func (c *Conn) flushUnsentRequests(err error) {
	for {
		select {
		default:
			return
		case req := <-c.sendChan:
			req.recvChan <- response{-1, err}
		}
	}
}

// Send error to all pending requests and clear request map
func (c *Conn) flushRequests(err error) {
	c.requestsLock.Lock()
	for _, req := range c.requests {
		req.recvChan <- response{-1, err}
	}
	c.requests = make(map[int32]*request)
	c.requestsLock.Unlock()
}

// Send event to all interested watchers
func (c *Conn) notifyWatchers(ev Event) {
	// Walk through all watchers and collect the ones interested in this event.
	var persistentWatchers []watcher
	var nonPersistentWatchers []watcher
	func() {
		c.watchersLock.Lock()
		defer c.watchersLock.Unlock()

		for key, watchers := range c.watchersByKey {
			if key.kind.isPersistent() {
				// Persistent watchers are notified of all events.
				if key.kind.isRecursive() {
					if strings.HasPrefix(ev.Path, key.path) { // Recursive watchers match paths by prefix.
						persistentWatchers = append(persistentWatchers, watchers...)
					}
				} else if ev.Path == key.path { // Non-recursive watchers match paths exactly.
					persistentWatchers = append(persistentWatchers, watchers...)
				}
				continue
			}

			// Non-persistent watchers match specific events types and exact paths.
			if key.kind.handlesEventType(ev.Type) && key.path == ev.Path {
				nonPersistentWatchers = append(nonPersistentWatchers, watchers...)
				delete(c.watchersByKey, key) // Remove watchers from map, since they can only be notified once.
			}
		}
	}() // outside watchersLock.

	// Notify and close non-persistent watchers.
	for _, w := range nonPersistentWatchers {
		_ = w.notify(ev)
		w.close()
	}

	// Notify persistent watchers, collecting any dead ones.
	var deadWatchers []watcher
	for _, w := range persistentWatchers {
		if !w.notify(ev) {
			deadWatchers = append(deadWatchers, w)
		}
	}

	if len(deadWatchers) > 0 {
		// Remove any dead watchers that can no longer receive events.
		// This must be done in the background to avoid deadlocking the recv loop.
		go func() {
			for _, w := range deadWatchers {
				_ = c.RemoveWatch(context.Background(), w.eventChan()) // Ignore errors.
			}
		}()
	}
}

// Send EventNotWatching to all watchers and clear watchersByKey.
func (c *Conn) invalidateWatchers(err error) {
	c.watchersLock.Lock()
	defer c.watchersLock.Unlock()

	// All watchers receive EventNotWatching, and then are closed.
	for key, watchers := range c.watchersByKey {
		ev := Event{Type: EventNotWatching, State: StateDisconnected, Path: key.path, Err: err}
		c.sendEvent(ev) // also publish globally
		for _, w := range watchers {
			_ = w.notify(ev) // We don't care if the event cannot be delivered.
			w.close()
		}
	}

	// Reset watchersByKey map.
	c.watchersByKey = make(map[watcherKey][]watcher)
}

// Send EventNotWatching to any watchers with the `invalidateOnDisconnect` option set.
func (c *Conn) invalidateWatchersOnDisconnect() {
	c.watchersLock.Lock()
	defer c.watchersLock.Unlock()

	for key, watchers := range c.watchersByKey {
		for i, w := range watchers {
			if !w.options().invalidateOnDisconnect {
				continue // ignore
			}

			// This watcher must be invalidated.
			watchers = append(watchers[:i], watchers[i+1:]...)
			if len(watchers) == 0 {
				// No more watchers remain for key, so remove it from the map.
				delete(c.watchersByKey, key)
			} else {
				// Store the updated list of watchers for key.
				c.watchersByKey[key] = watchers
			}

			// Signal consumer that the watcher has been removed.
			ev := Event{Type: EventNotWatching, State: StateDisconnected, Path: key.path, Err: nil}
			_ = w.notify(ev) // Best effort, only.
			w.close()
			c.sendEvent(ev)
		}
	}
}

func (c *Conn) restoreWatches() {
	c.watchersLock.Lock()
	defer c.watchersLock.Unlock()

	if len(c.watchersByKey) == 0 {
		return // Nothing to do.
	}

	// NB: A ZK server, by default, rejects packets >1mb. So, if we have too
	// many watches to reset, we need to break this up into multiple packets
	// to avoid hitting that limit. Mirroring the Java client behavior: we are
	// conservative in that we limit requests to 128kb (since server limit is
	// is actually configurable and could conceivably be configured smaller
	// than default of 1mb).
	limit := 128 * 1024
	if c.setWatchLimit > 0 {
		limit = c.setWatchLimit
	}

	var reqs []*setWatches2Request
	var req *setWatches2Request
	var sizeSoFar int

	n := 0
	for key := range c.watchersByKey {
		addlLen := 4 + len(key.path)
		if req == nil || sizeSoFar+addlLen > limit {
			if req != nil {
				// add to set of requests that we'll send
				reqs = append(reqs, req)
			}
			sizeSoFar = 28 // fixed overhead of a set-watches packet
			req = &setWatches2Request{
				RelativeZxid:               c.lastZxid,
				DataWatches:                make([]string, 0),
				ExistWatches:               make([]string, 0),
				ChildWatches:               make([]string, 0),
				PersistentWatches:          make([]string, 0),
				PersistentRecursiveWatches: make([]string, 0),
			}
		}
		sizeSoFar += addlLen
		switch key.kind {
		case watcherKindData:
			req.DataWatches = append(req.DataWatches, key.path)
		case watcherKindExist:
			req.ExistWatches = append(req.ExistWatches, key.path)
		case watcherKindChildren:
			req.ChildWatches = append(req.ChildWatches, key.path)
		case watcherKindPersistent:
			req.PersistentWatches = append(req.PersistentWatches, key.path)
		case watcherKindPersistentRecursive:
			req.PersistentRecursiveWatches = append(req.PersistentRecursiveWatches, key.path)
		}
		n++
	}
	if n == 0 {
		return
	}
	if req != nil { // don't forget any trailing packet we were building
		reqs = append(reqs, req)
	}

	if c.setWatchCallback != nil {
		c.setWatchCallback(reqs)
	}

	go func() {
		// TODO: Pipeline these so queue all of them up before waiting on any
		// response. That will require some investigation to make sure there
		// aren't failure modes where a blocking write to the channel of requests
		// could hang indefinitely and cause this goroutine to leak...
		for _, req = range reqs {
			_, _, err := c.request(context.Background(), opSetWatches2, req, nil, nil)
			if err != nil {
				c.logger.Error("failed to set previous watches", "error", err)
				break
			}
		}
	}()
}

func (c *Conn) authenticate() error {
	buf := make([]byte, 256)

	// Encode and send a connect request.
	n, err := encodePacket(buf[4:], &connectRequest{
		ProtocolVersion: protocolVersion,
		LastZxidSeen:    c.lastZxid,
		TimeOut:         c.sessionTimeoutMs,
		SessionID:       c.SessionID(),
		Passwd:          c.passwd,
	})
	if err != nil {
		return err
	}

	binary.BigEndian.PutUint32(buf[:4], uint32(n))

	if _, err = writeWithDeadline(c.conn, buf[:n+4], c.ioTimeout*10); err != nil {
		return err
	}

	// Receive and decode a connect response.
	if _, err = readFullWithDeadline(c.conn, buf[:4], c.ioTimeout*10); err != nil {
		return err
	}

	blen := int(binary.BigEndian.Uint32(buf[:4]))
	if cap(buf) < blen {
		buf = make([]byte, blen)
	}

	_, err = io.ReadFull(c.conn, buf[:blen])
	if err != nil {
		return err
	}

	r := connectResponse{}
	_, err = decodePacket(buf[:blen], &r)
	if err != nil {
		return err
	}
	if r.SessionID == 0 {
		c.setState(StateExpired)
		return ErrSessionExpired
	}

	c.sessionID.Store(r.SessionID)
	c.setTimeouts(r.TimeOut)
	c.passwd = r.Passwd
	c.setState(StateHasSession)

	return nil
}

func (c *Conn) resetSession(err error) {
	c.sessionID.Store(int64(0))
	c.passwd = emptyPassword
	c.lastZxid = 0
	c.invalidateWatchers(err)
}

func (c *Conn) sendData(req *request) error {
	header := &requestHeader{req.xid, req.opcode}
	n, err := encodePacket(c.buf[4:], header)
	if err != nil {
		req.recvChan <- response{-1, err}
		return nil
	}

	if req.pkt != nil { // some requests don't have a body (header only)
		n2, err := encodePacket(c.buf[4+n:], req.pkt)
		if err != nil {
			req.recvChan <- response{-1, err}
			return nil
		}
		n += n2
	}

	binary.BigEndian.PutUint32(c.buf[:4], uint32(n))

	c.requestsLock.Lock()
	select {
	case <-c.closeChan:
		req.recvChan <- response{-1, ErrConnectionClosed}
		c.requestsLock.Unlock()
		return ErrConnectionClosed
	default:
	}
	c.requests[req.xid] = req
	c.requestsLock.Unlock()

	if _, err = writeWithDeadline(c.conn, c.buf[:n+4], c.ioTimeout); err != nil {
		req.recvChan <- response{-1, err}
		_ = c.conn.Close()
		return err
	}

	return nil
}

func (c *Conn) sendLoop() error {
	pingTicker := time.NewTicker(c.pingInterval)
	defer pingTicker.Stop()

	for {
		select {
		case req := <-c.sendChan:
			if err := c.sendData(req); err != nil {
				return err
			}
		case <-pingTicker.C:
			n, err := encodePacket(c.buf[4:], &requestHeader{Xid: -2, Opcode: opPing})
			if err != nil {
				panic("zk: opPing should never fail to serialize, but saw: " + err.Error())
			}

			binary.BigEndian.PutUint32(c.buf[:4], uint32(n))

			if _, err = writeWithDeadline(c.conn, c.buf[:n+4], c.ioTimeout); err != nil {
				c.conn.Close()
				return err
			}
		case <-c.closeChan:
			return nil
		}
	}
}

func (c *Conn) recvLoop(conn net.Conn) error {
	sz := bufferSize
	if c.maxBufferSize > 0 && sz > c.maxBufferSize {
		sz = c.maxBufferSize
	}
	buf := make([]byte, sz)
	for {
		// package length
		if _, err := readFullWithDeadline(conn, buf[:4], c.ioTimeout); err != nil {
			return fmt.Errorf("failed to read from connection: %w", err)
		}

		blen := int(binary.BigEndian.Uint32(buf[:4]))
		if cap(buf) < blen {
			if c.maxBufferSize > 0 && blen > c.maxBufferSize {
				return fmt.Errorf("received packet from server with length %d, which exceeds max buffer size %d", blen, c.maxBufferSize)
			}
			buf = make([]byte, blen)
		}

		if _, err := readFullWithDeadline(conn, buf[:blen], c.ioTimeout); err != nil {
			return err
		}

		res := responseHeader{}
		if _, err := decodePacket(buf[:16], &res); err != nil {
			return err
		}

		if res.Xid == -1 {
			we := &watcherEvent{}
			if _, err := decodePacket(buf[16:blen], we); err != nil {
				return err
			}
			ev := Event{
				Type:  we.Type,
				State: we.State,
				Path:  we.Path,
				Err:   nil,
			}
			c.sendEvent(ev)
			c.notifyWatchers(ev)
		} else if res.Xid == -2 {
			// Ping response. Ignore.
		} else if res.Xid < 0 {
			c.logger.Error("xid < 0 but not ping or watcher event", "xid", res.Xid)
		} else {
			if res.Zxid > 0 {
				c.lastZxid = res.Zxid
			}

			c.requestsLock.Lock()
			req, ok := c.requests[res.Xid]
			if ok {
				delete(c.requests, res.Xid)
			}
			c.requestsLock.Unlock()

			if !ok {
				c.logger.Error("response for unknown request", "xid", res.Xid)
			} else {
				var err error
				if res.Err != 0 {
					err = res.Err.toError()
				} else if req.recvStruct != nil { // only decode if we have a struct to decode into
					_, err = decodePacket(buf[16:blen], req.recvStruct)
				}
				if req.recvFunc != nil {
					req.recvFunc(req, &res, err)
				}
				req.recvChan <- response{res.Zxid, err}
				if req.opcode == opClose {
					return io.EOF
				}
			}
		}
	}
}

func (c *Conn) nextXid() int32 {
	return int32(c.xid.Add(1) & 0x7fffffff)
}

func (c *Conn) addWatcher(path string, kind watcherKind, opts watcherOptions) <-chan Event {
	key := watcherKey{path, kind}
	var w watcher

	stallCallback := opts.stallCallback
	opts.stallCallback = func() {
		// Report watcher stalls.
		c.sendEvent(Event{Type: EventWatcherStalled, Path: path, State: c.State()})
		c.logger.Error("persistent watcher has stalled", "kind", kind, "path", path)

		if stallCallback != nil { // Call the supplied callback
			stallCallback()
		}
	}

	if kind.isPersistent() {
		w = newPersistentWatcher(opts)
	} else {
		w = newFireOnceWatcher(opts)
	}

	c.watchersLock.Lock()
	defer c.watchersLock.Unlock()

	c.watchersByKey[key] = append(c.watchersByKey[key], w)

	return w.eventChan()
}

// removeWatcher will attempt to remove a watcher associated with the given event channel.
// If the watcher is successfully removed, its watcherKey will be returned along
// with the number of remaining watchers with the same watcherKey.
// It is assumed that the caller has already acquired the watchersLock.
func (c *Conn) removeWatcher(ech <-chan Event) (bool, watcherKey, int) {
	for key, watchers := range c.watchersByKey {
		for i, w := range watchers {
			if w.eventChan() != ech {
				continue // Not the watcher we're looking for.
			}

			// Found the watcher associated with the event channel.
			// Let's remove it from the list of watchers.
			watchers = append(watchers[:i], watchers[i+1:]...)
			remaining := len(watchers)
			if remaining == 0 {
				// No more watchers remain for key, so remove it from the map.
				delete(c.watchersByKey, key)
			} else {
				// Store the updated list of watchers for key.
				c.watchersByKey[key] = watchers
			}

			// Signal consumer that the watcher has been removed.
			ev := Event{Type: EventNotWatching, State: c.State(), Path: key.path, Err: nil}
			_ = w.notify(ev) // Best effort, only.
			w.close()
			c.sendEvent(ev)

			return true, key, remaining
		}
	}

	return false, watcherKey{}, 0 // No watcher found for channel.
}

func (c *Conn) queueRequest(ctx context.Context, opcode int32, req any, res any, recvFunc func(*request, *responseHeader, error)) <-chan response {
	rq := &request{
		xid:        c.nextXid(),
		opcode:     opcode,
		pkt:        req,
		recvStruct: res,
		recvChan:   make(chan response, 2),
		recvFunc:   recvFunc,
	}

	switch opcode {
	case opClose:
		// always attempt to send close ops.
		select {
		case c.sendChan <- rq:
		case <-time.After(c.connectTimeout * 2):
			c.logger.Error("gave up trying to send opClose to server")
			rq.recvChan <- response{-1, ErrConnectionClosed}
		case <-ctx.Done():
			rq.recvChan <- response{-1, ctx.Err()}
		}
	default:
		// otherwise avoid deadlocks for dumb clients who aren't aware that
		// the ZK connection is closed yet.
		select {
		case <-c.shouldQuit:
			rq.recvChan <- response{-1, ErrConnectionClosed}
		case <-ctx.Done():
			rq.recvChan <- response{-1, ctx.Err()}
		case c.sendChan <- rq:
			// check for a tie
			select {
			case <-c.shouldQuit:
				// maybe the caller gets this, maybe not- we tried.
				rq.recvChan <- response{-1, ErrConnectionClosed}
			default:
			}
		}
	}
	return rq.recvChan
}

func (c *Conn) request(
	ctx context.Context,
	opcode int32,
	req any,
	res any,
	recvFunc func(*request, *responseHeader, error),
) (xid int64, aborted bool, err error) {
	// NOTE: queueRequest() can be racy due to access to `res` fields concurrently w/ the async response processor.
	// Callers must not read from `res` if this function returns aborted=true. Doing so will trip race detector.
	recv := c.queueRequest(ctx, opcode, req, res, recvFunc)

	select {
	case r := <-recv:
		return r.zxid, false, r.err
	case <-ctx.Done(): // Aborts active request.
		return -1, true, ctx.Err()
	case <-c.shouldQuit: // Aborts active request.
		return -1, true, ErrConnectionClosed
	}
}

// AddAuth adds an authentication config to the connection.
func (c *Conn) AddAuth(ctx context.Context, scheme string, auth []byte) error {
	_, _, err := c.request(ctx, opSetAuth, &setAuthRequest{Type: 0, Scheme: scheme, Auth: auth}, nil, nil)
	if err != nil {
		return err
	}

	// Remember authdata so that it can be re-submitted on reconnect
	//
	// FIXME(prozlach): For now we treat "userfoo:passbar" and "userfoo:passbar2"
	// as two different entries, which will be re-submitted on reconnect. Some
	// research is needed on how ZK treats these cases and
	// then maybe switch to something like "map[username] = password" to allow
	// only single password for given user with users being unique.
	obj := authCreds{
		scheme: scheme,
		auth:   auth,
	}

	c.credsMu.Lock()
	c.creds = append(c.creds, obj)
	c.credsMu.Unlock()

	return nil
}

// AddWatch creates a persistent (optionally recursive) watch at the given path.
func (c *Conn) AddWatch(ctx context.Context, path string, recursive bool, options ...WatcherOption) (<-chan Event, error) {
	if err := validatePath(path, false); err != nil {
		return nil, err
	}

	var ech <-chan Event
	mode := addWatchModePersistent
	kind := watcherKindPersistent
	if recursive {
		mode = addWatchModePersistentRecursive
		kind = watcherKindPersistentRecursive
	}

	wopts := watcherOptions{}
	for _, opt := range options {
		opt(&wopts)
	}

	_, _, err := c.request(ctx, opAddWatch, &addWatchRequest{Path: path, Mode: mode}, nil, func(req *request, res *responseHeader, err error) {
		if err == nil {
			ech = c.addWatcher(path, kind, wopts)
		}
	})
	if err != nil {
		return nil, err
	}

	return ech, err
}

// RemoveWatch removes a watch associated with the given channel.
// Note: This method works for any type of watch, not just persistent ones.
func (c *Conn) RemoveWatch(ctx context.Context, ech <-chan Event) error {
	c.watchersLock.Lock()

	// Remove the watcher from the client, first.
	ok, key, remaining := c.removeWatcher(ech)

	// Don't keep the lock during the request,
	// may end up in a dead lock if another events is received before the request answer.
	c.watchersLock.Unlock()

	if !ok {
		return ErrNoWatcher
	}

	if remaining == 0 {
		// No more watchers remain for the watcherKey, so we can remove the watch from the server.
		req := &removeWatchesRequest{Path: key.path}
		switch key.kind {
		case watcherKindData:
			req.Type = removeWatchTypeData
		case watcherKindChildren:
			req.Type = removeWatchTypeChildren
		default:
			req.Type = removeWatchTypePersistent
		}
		_, _, err := c.request(ctx, opRemoveWatches, req, nil, nil)
		if err != nil {
			return err
		}
	}

	return nil
}

// Children returns the children of a znode.
func (c *Conn) Children(ctx context.Context, path string) ([]string, *Stat, error) {
	if err := validatePath(path, false); err != nil {
		return nil, nil, err
	}

	res := &getChildren2Response{}
	_, aborted, err := c.request(ctx, opGetChildren2, &getChildren2Request{Path: path, Watch: false}, res, nil)
	if err != nil && aborted {
		return nil, nil, err // Request aborted, so we cannot read from `res` without risking a data race.
	}

	return res.Children, &res.Stat, err
}

// ChildrenW returns the children of a znode and sets a watch.
func (c *Conn) ChildrenW(ctx context.Context, path string) ([]string, *Stat, <-chan Event, error) {
	if err := validatePath(path, false); err != nil {
		return nil, nil, nil, err
	}

	var ech <-chan Event
	res := &getChildren2Response{}
	_, aborted, err := c.request(ctx, opGetChildren2, &getChildren2Request{Path: path, Watch: true}, res, func(req *request, res *responseHeader, err error) {
		if err == nil {
			ech = c.addWatcher(path, watcherKindChildren, watcherOptions{})
		}
	})
	if err != nil && aborted {
		return nil, nil, nil, err // Request aborted, so we cannot read from `res` without risking a data race.
	}

	return res.Children, &res.Stat, ech, err
}

// Get gets the contents of a znode.
func (c *Conn) Get(ctx context.Context, path string) ([]byte, *Stat, error) {
	if err := validatePath(path, false); err != nil {
		return nil, nil, err
	}

	res := &getDataResponse{}
	_, aborted, err := c.request(ctx, opGetData, &GetDataRequest{Path: path, Watch: false}, res, nil)
	if err != nil && aborted {
		return nil, nil, err // Request aborted, so we cannot read from `res` without risking a data race.
	}

	return res.Data, &res.Stat, err
}

// GetW returns the contents of a znode and sets a watch
func (c *Conn) GetW(ctx context.Context, path string) ([]byte, *Stat, <-chan Event, error) {
	if err := validatePath(path, false); err != nil {
		return nil, nil, nil, err
	}

	var ech <-chan Event
	res := &getDataResponse{}
	_, aborted, err := c.request(ctx, opGetData, &GetDataRequest{Path: path, Watch: true}, res, func(req *request, res *responseHeader, err error) {
		if err == nil {
			ech = c.addWatcher(path, watcherKindData, watcherOptions{})
		}
	})
	if err != nil && aborted {
		return nil, nil, nil, err // Request aborted, so we cannot read from `res` without risking a data race.
	}

	return res.Data, &res.Stat, ech, err
}

// Set updates the contents of a znode.
func (c *Conn) Set(ctx context.Context, path string, data []byte, version int32) (*Stat, error) {
	if err := validatePath(path, false); err != nil {
		return nil, err
	}

	res := &setDataResponse{}
	_, aborted, err := c.request(ctx, opSetData, &SetDataRequest{path, data, version}, res, nil)
	if err != nil && aborted {
		return nil, err // Request aborted, so we cannot read from `res` without risking a data race.
	}

	return &res.Stat, err
}

// Create creates a znode.
// The returned path is the new path assigned by the server, it may not be the
// same as the input, for example when creating a sequence znode the returned path
// will be the input path with a sequence number appended.
func (c *Conn) Create(ctx context.Context, path string, data []byte, flags int32, acl []ACL) (string, error) {
	if err := validatePath(path, flags&FlagSequence == FlagSequence); err != nil {
		return "", err
	}

	res := &createResponse{}
	_, aborted, err := c.request(ctx, opCreate, &CreateRequest{path, data, acl, flags}, res, nil)
	if err != nil && aborted {
		return "", err // Request aborted, so we cannot read from `res` without risking a data race.
	}

	return res.Path, err
}

// CreateContainer creates a container znode and returns the path.
func (c *Conn) CreateContainer(ctx context.Context, path string, data []byte, flags int32, acl []ACL) (string, error) {
	if err := validatePath(path, flags&FlagSequence == FlagSequence); err != nil {
		return "", err
	}
	if flags&FlagTTL != FlagTTL {
		return "", ErrInvalidFlags
	}

	res := &createResponse{}
	_, aborted, err := c.request(ctx, opCreateContainer, &CreateContainerRequest{path, data, acl, flags}, res, nil)
	if err != nil && aborted {
		return "", err // Request aborted, so we cannot read from `res` without risking a data race.
	}

	return res.Path, err
}

// CreateTTL creates a TTL znode, which will be automatically deleted by server after the TTL.
func (c *Conn) CreateTTL(ctx context.Context, path string, data []byte, flags int32, acl []ACL, ttl time.Duration) (string, error) {
	if err := validatePath(path, flags&FlagSequence == FlagSequence); err != nil {
		return "", err
	}
	if flags&FlagTTL != FlagTTL {
		return "", ErrInvalidFlags
	}

	res := &createResponse{}
	_, aborted, err := c.request(ctx, opCreateTTL, &CreateTTLRequest{path, data, acl, flags, ttl.Milliseconds()}, res, nil)
	if err != nil && aborted {
		return "", err // Request aborted, so we cannot read from `res` without risking a data race.
	}

	return res.Path, err
}

// CreateProtectedEphemeralSequential fixes a race condition if the server crashes
// after it creates the node. On reconnect the session may still be valid so the
// ephemeral node still exists. Therefore, on reconnect we need to check if a node
// with a GUID generated on create exists.
func (c *Conn) CreateProtectedEphemeralSequential(ctx context.Context, path string, data []byte, acl []ACL) (string, error) {
	if err := validatePath(path, true); err != nil {
		return "", err
	}

	var guid [16]byte
	_, err := io.ReadFull(rand.Reader, guid[:16])
	if err != nil {
		return "", err
	}
	guidStr := fmt.Sprintf("%x", guid)

	parts := strings.Split(path, "/")
	parts[len(parts)-1] = fmt.Sprintf("%s%s-%s", protectedPrefix, guidStr, parts[len(parts)-1])
	rootPath := strings.Join(parts[:len(parts)-1], "/")
	protectedPath := strings.Join(parts, "/")

	var newPath string
	for range 3 {
		newPath, err = c.Create(ctx, protectedPath, data, FlagEphemeral|FlagSequence, acl)
		if errors.Is(err, ErrSessionExpired) {
			// No need to search for the node since it can't exist. Just try again.
		} else if errors.Is(err, ErrConnectionClosed) {
			children, _, err := c.Children(ctx, rootPath)
			if err != nil {
				// Return the path with GUID for error handling
				//
				// If the connection is closed, it may re-establish, and
				// the session might still be active, so we should
				// return the base path for clients to recover from that
				// situation.
				return protectedPath, err
			}
			for _, p := range children {
				parts := strings.Split(p, "/")
				if pth := parts[len(parts)-1]; strings.HasPrefix(pth, protectedPrefix) {
					if g := pth[len(protectedPrefix) : len(protectedPrefix)+32]; g == guidStr {
						return rootPath + "/" + p, nil
					}
				}
			}
		} else if err == nil {
			return newPath, nil
		} else {
			return protectedPath, err
		}
	}
	return "", err
}

// Delete deletes a znode.
func (c *Conn) Delete(ctx context.Context, path string, version int32) error {
	if err := validatePath(path, false); err != nil {
		return err
	}

	_, _, err := c.request(ctx, opDelete, &DeleteRequest{path, version}, nil, nil)
	return err
}

// Exists tells the existence of a znode.
func (c *Conn) Exists(ctx context.Context, path string) (bool, *Stat, error) {
	if err := validatePath(path, false); err != nil {
		return false, nil, err
	}

	res := &existsResponse{}
	_, aborted, err := c.request(ctx, opExists, &existsRequest{Path: path, Watch: false}, res, nil)
	if err != nil && aborted {
		return false, nil, err // Request aborted, so we cannot read from `res` without risking a data race.
	}

	exists := true
	if errors.Is(err, ErrNoNode) {
		exists = false
		err = nil
	}

	return exists, &res.Stat, err
}

// ExistsW tells the existence of a znode and sets a watch.
func (c *Conn) ExistsW(ctx context.Context, path string) (bool, *Stat, <-chan Event, error) {
	if err := validatePath(path, false); err != nil {
		return false, nil, nil, err
	}

	var ech <-chan Event
	res := &existsResponse{}
	_, aborted, err := c.request(ctx, opExists, &existsRequest{Path: path, Watch: true}, res, func(req *request, res *responseHeader, err error) {
		if err == nil {
			ech = c.addWatcher(path, watcherKindData, watcherOptions{})
		} else if errors.Is(err, ErrNoNode) {
			ech = c.addWatcher(path, watcherKindExist, watcherOptions{})
		}
	})
	if err != nil && aborted {
		return false, nil, nil, err // Request aborted, so we cannot read from `res` without risking a data race.
	}

	exists := true
	if errors.Is(err, ErrNoNode) {
		exists = false
		err = nil
	}

	return exists, &res.Stat, ech, err
}

// GetACL gets the ACLs of a znode.
func (c *Conn) GetACL(ctx context.Context, path string) ([]ACL, *Stat, error) {
	if err := validatePath(path, false); err != nil {
		return nil, nil, err
	}

	res := &getAclResponse{}
	_, aborted, err := c.request(ctx, opGetACL, &getAclRequest{Path: path}, res, nil)
	if err != nil && aborted {
		return nil, nil, err // Request aborted, so we cannot read from `res` without risking a data race.
	}

	return res.Acl, &res.Stat, err
}

// SetACL updates the ACLs of a znode.
func (c *Conn) SetACL(ctx context.Context, path string, acl []ACL, version int32) (*Stat, error) {
	if err := validatePath(path, false); err != nil {
		return nil, err
	}

	res := &setAclResponse{}
	_, aborted, err := c.request(ctx, opSetACL, &setAclRequest{Path: path, Acl: acl, Version: version}, res, nil)
	if err != nil && aborted {
		return nil, err // Request aborted, so we cannot read from `res` without risking a data race.
	}

	return &res.Stat, err
}

// Sync flushes the channel between process and the leader of a given znode,
// you may need it if you want identical views of ZooKeeper data for 2 client instances.
// Please refer to the "Consistency Guarantees" section of ZK document for more details.
func (c *Conn) Sync(ctx context.Context, path string) (string, error) {
	if err := validatePath(path, false); err != nil {
		return "", err
	}

	res := &syncResponse{}
	_, aborted, err := c.request(ctx, opSync, &syncRequest{Path: path}, res, nil)
	if err != nil && aborted {
		return "", err // Request aborted, so we cannot read from `res` without risking a data race.
	}

	return res.Path, err
}

// MultiResponse is the result of a Multi or MultiRead call.
type MultiResponse struct {
	Path     string   // The path of the znode. Only set for CreateRequest.
	Children []string // The children of the znode. Only set for GetChildrenRequest.
	Stat     *Stat    // The stat of the znode. Only set for CreateRequest and SetDataRequest
	Data     []byte   // The data of the znode. Only set for GetDataRequest.
	Error    error    // The error of the operation. Applies to all request types.
}

// Multi executes multiple ZooKeeper operations or none of them. The provided
// ops must be one of *CreateRequest, *DeleteRequest, *SetDataRequest, or
// *CheckVersionRequest.
func (c *Conn) Multi(ctx context.Context, ops ...any) ([]MultiResponse, error) {
	req := &multiRequest{
		Ops:        make([]multiRequestOp, 0, len(ops)),
		DoneHeader: multiHeader{Type: -1, Done: true, Err: -1},
	}

	for _, op := range ops {
		var opCode int32
		switch op.(type) {
		case *CreateRequest:
			opCode = opCreate
		case *SetDataRequest:
			opCode = opSetData
		case *DeleteRequest:
			opCode = opDelete
		case *CheckVersionRequest:
			opCode = opCheck
		default:
			return nil, fmt.Errorf("operation type %T is not supported by multi", op)
		}
		req.Ops = append(req.Ops, multiRequestOp{multiHeader{opCode, false, -1}, op})
	}

	res := &multiResponse{}
	_, aborted, err := c.request(ctx, opMulti, req, res, nil)
	if err != nil && aborted {
		return nil, err // Request aborted, so we cannot read from `res` without risking a data race.
	}

	mr := make([]MultiResponse, len(res.Ops))
	for i, op := range res.Ops {
		mr[i] = MultiResponse{Error: op.Err.toError()}
		if mr[i].Error != nil {
			continue // No other fields expected to be set.
		}
		switch op.Header.Type {
		case opCreate:
			if r, ok := op.Resp.(*createResponse); ok {
				mr[i].Path = r.Path
			}
		case opSetData:
			if r, ok := op.Resp.(*setDataResponse); ok {
				mr[i].Stat = &r.Stat
			}
		}
	}

	return mr, err
}

// MultiRead executes multiple ZooKeeper read operations.
// The provided ops must be one of *GetDataRequest or *GetChildrenRequest.
func (c *Conn) MultiRead(ctx context.Context, ops ...any) ([]MultiResponse, error) {
	req := &multiRequest{
		Ops:        make([]multiRequestOp, 0, len(ops)),
		DoneHeader: multiHeader{Type: -1, Done: true, Err: -1},
	}

	for _, op := range ops {
		var opCode int32
		switch op.(type) {
		case *GetDataRequest:
			opCode = opGetData
		case *GetChildrenRequest:
			opCode = opGetChildren
		default:
			return nil, fmt.Errorf("operation type %T is not supported by multi", op)
		}
		req.Ops = append(req.Ops, multiRequestOp{multiHeader{opCode, false, -1}, op})
	}

	res := &multiResponse{}
	_, aborted, err := c.request(ctx, opMultiRead, req, res, nil)
	if err != nil && aborted {
		return nil, err // Request aborted, so we cannot read from `res` without risking a data race.
	}

	mr := make([]MultiResponse, len(res.Ops))
	for i, op := range res.Ops {
		mr[i] = MultiResponse{Error: op.Err.toError()}
		if mr[i].Error != nil {
			continue // No other fields expected to be set.
		}
		switch op.Header.Type {
		case opGetData:
			if r, ok := op.Resp.(*getDataResponse); ok {
				mr[i].Data = r.Data
				mr[i].Stat = &r.Stat
			}
		case opGetChildren:
			if r, ok := op.Resp.(*getChildrenResponse); ok {
				mr[i].Children = r.Children
			}
		}
	}
	return mr, err
}

// IncrementalReconfig is the zookeeper reconfiguration api that allows adding and removing servers
// by lists of members. For more info refer to the ZK documentation.
//
// An optional version allows for conditional reconfigurations, -1 ignores the condition.
//
// Returns the new configuration znode stat.
func (c *Conn) IncrementalReconfig(ctx context.Context, joining, leaving []string, version int64) (*Stat, error) {
	// TODO: validate the shape of the member string to give early feedback.
	request := &reconfigRequest{
		JoiningServers: []byte(strings.Join(joining, ",")),
		LeavingServers: []byte(strings.Join(leaving, ",")),
		CurConfigId:    version,
	}

	return c.internalReconfig(ctx, request)
}

// Reconfig is the non-incremental update functionality for Zookeeper where the list provided
// is the entire new member list. For more info refer to the ZK documentation.
//
// An optional version allows for conditional reconfigurations, -1 ignores the condition.
//
// Returns the new configuration znode stat.
func (c *Conn) Reconfig(ctx context.Context, members []string, version int64) (*Stat, error) {
	req := &reconfigRequest{
		NewMembers:  []byte(strings.Join(members, ",")),
		CurConfigId: version,
	}

	return c.internalReconfig(ctx, req)
}

func (c *Conn) internalReconfig(ctx context.Context, req *reconfigRequest) (*Stat, error) {
	resp := &reconfigReponse{}
	_, aborted, err := c.request(ctx, opReconfig, req, resp, nil)
	if err != nil && aborted {
		return nil, err // Request aborted, so we cannot read from `res` without risking a data race.
	}

	return &resp.Stat, err
}

// Server returns the current or last-connected server name.
func (c *Conn) Server() string {
	c.serverMu.Lock()
	defer c.serverMu.Unlock()
	return c.server
}

// Walker returns a new TreeWalker used to traverse the tree of nodes at the given path.
// Nodes are traversed in the specified order (depth-first or breadth-first).
// For large trees, use BatchWalker instead.
func (c *Conn) Walker(path string, order TraversalOrder) *TreeWalker {
	return NewTreeWalker(c.Children, path, order)
}

// BatchWalker returns a new BatchTreeWalker used to traverse the tree of nodes at the given path.
// Nodes are traversed in breadth-first order, in batches up to the given size.
// This method is more efficient than Walker when the number of nodes is large.
func (c *Conn) BatchWalker(path string, batchSize int) *BatchTreeWalker {
	return NewBatchTreeWalker(c, path, batchSize)
}

func resendZkAuth(ctx context.Context, c *Conn) error {
	shouldCancel := func() bool {
		select {
		case <-c.shouldQuit:
			return true
		case <-c.closeChan:
			return true
		default:
			return false
		}
	}

	c.credsMu.Lock()
	defer c.credsMu.Unlock()

	if c.logInfo {
		c.logger.Info("re-submitting credentials after reconnect", "count", len(c.creds))
	}

	for _, cred := range c.creds {
		// return early before attempting to send request.
		if shouldCancel() {
			return nil
		}
		// do not use the public API for auth since it depends on the send/recv loops
		// that are waiting for this to return
		resChan, err := c.sendRequest(
			opSetAuth,
			&setAuthRequest{Type: 0,
				Scheme: cred.scheme,
				Auth:   cred.auth,
			},
			nil, /* res*/
			nil, /* recvFunc*/
		)
		if err != nil {
			return fmt.Errorf("failed to send auth request: %w", err)
		}

		var res response
		select {
		case res = <-resChan:
		case <-c.closeChan:
			c.logger.Info("recv closed, cancel re-submitting credentials")
			return nil
		case <-c.shouldQuit:
			c.logger.Info("should quit, cancel re-submitting credentials")
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
		if res.err != nil {
			return fmt.Errorf("failed connection setAuth request: %w", res.err)
		}
	}

	return nil
}
