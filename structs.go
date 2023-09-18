package zk

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"reflect"
	"runtime"
	"strings"
	"time"
)

var (
	ErrUnhandledFieldType = errors.New("zk: unhandled field type")
	ErrPtrExpected        = errors.New("zk: encode/decode expect a non-nil pointer to struct")
	ErrShortBuffer        = errors.New("zk: buffer too small")
)

type defaultLogger struct{}

func (defaultLogger) Printf(format string, v ...interface{}) {
	log.Output(3, fmt.Sprintf(format, v...))
}

type ACL struct {
	Perms  int32
	Scheme string
	ID     string
}

type Stat struct {
	Czxid          int64 // The zxid of the change that caused this znode to be created.
	Mzxid          int64 // The zxid of the change that last modified this znode.
	Ctime          int64 // The time in milliseconds from epoch when this znode was created.
	Mtime          int64 // The time in milliseconds from epoch when this znode was last modified.
	Version        int32 // The number of changes to the data of this znode.
	Cversion       int32 // The number of changes to the children of this znode.
	Aversion       int32 // The number of changes to the ACL of this znode.
	EphemeralOwner int64 // The session id of the owner of this znode if the znode is an ephemeral node. If it is not an ephemeral node, it will be zero.
	DataLength     int32 // The length of the data field of this znode.
	NumChildren    int32 // The number of children of this znode.
	Pzxid          int64 // last modified children
}

// ServerClient is the information for a single Zookeeper client and its session.
// This is used to parse/extract the output fo the `cons` command.
type ServerClient struct {
	Queued        int64
	Received      int64
	Sent          int64
	SessionID     int64
	Lcxid         int64
	Lzxid         int64
	Timeout       int32
	LastLatency   int32
	MinLatency    int32
	AvgLatency    int32
	MaxLatency    int32
	Established   time.Time
	LastResponse  time.Time
	Addr          string
	LastOperation string // maybe?
	Error         error
}

// ServerClients is a struct for the FLWCons() function. It's used to provide
// the list of Clients.
//
// This is needed because FLWCons() takes multiple servers.
type ServerClients struct {
	Clients []*ServerClient
	Error   error
}

// ServerStats is the information pulled from the Zookeeper `stat` command.
type ServerStats struct {
	Server      string
	Sent        int64
	Received    int64
	NodeCount   int64
	MinLatency  int64
	AvgLatency  float64
	MaxLatency  int64
	Connections int64
	Outstanding int64
	Epoch       int32
	Counter     int32
	BuildTime   time.Time
	Mode        Mode
	Version     string
	Error       error
}

type requestHeader struct {
	Xid    int32
	Opcode int32
}

type responseHeader struct {
	Xid  int32
	Zxid int64
	Err  ErrCode
}

type multiHeader struct {
	Type int32
	Done bool
	Err  ErrCode
}

type auth struct {
	Type   int32
	Scheme string
	Auth   []byte
}

// Generic request structs

type pathRequest struct {
	Path string
}

type PathVersionRequest struct {
	Path    string
	Version int32
}

type pathWatchRequest struct {
	Path  string
	Watch bool
}

type pathResponse struct {
	Path string
}

type statResponse struct {
	Stat *Stat
}

//

type CheckVersionRequest PathVersionRequest
type closeRequest struct{}
type closeResponse struct{}

type connectRequest struct {
	ProtocolVersion int32
	LastZxidSeen    int64
	TimeOut         int32
	SessionID       int64
	Passwd          []byte
}

type connectResponse struct {
	ProtocolVersion int32
	TimeOut         int32
	SessionID       int64
	Passwd          []byte
}

type CreateRequest struct {
	Path  string
	Data  []byte
	Acl   []ACL
	Flags int32
}

type CreateContainerRequest CreateRequest

type CreateTTLRequest struct {
	Path  string
	Data  []byte
	Acl   []ACL
	Flags int32
	Ttl   int64 // ms
}

type createResponse pathResponse
type create2Response struct {
	Path string
	Stat *Stat
}
type DeleteRequest PathVersionRequest
type deleteResponse struct{}

type errorResponse struct {
	Err int32
}

type existsRequest pathWatchRequest
type existsResponse statResponse
type getAclRequest pathRequest

type getAclResponse struct {
	Acl  []ACL
	Stat *Stat
}

type getChildrenRequest pathRequest

type getChildrenResponse struct {
	Children []string
}

type ReadOp interface {
	GetPath() string
	IsGetData() bool
	IsGetChildren() bool
	opCode() int32
}

type getChildren2Request pathWatchRequest
type GetChildrenOp string

func (g GetChildrenOp) IsGetData() bool {
	return false
}

func (g GetChildrenOp) IsGetChildren() bool {
	return true
}

func (g GetChildrenOp) GetPath() string {
	return string(g)
}

func (g GetChildrenOp) opCode() int32 {
	return opGetChildren
}

type getChildren2Response struct {
	Children []string
	Stat     *Stat
}

type getDataRequest pathWatchRequest
type GetDataOp string

func (g GetDataOp) IsGetData() bool {
	return true
}

func (g GetDataOp) IsGetChildren() bool {
	return false
}

func (g GetDataOp) GetPath() string {
	return string(g)
}

func (g GetDataOp) opCode() int32 {
	return opGetData
}

type getDataResponse struct {
	Data []byte
	Stat *Stat
}

type getMaxChildrenRequest pathRequest

type getMaxChildrenResponse struct {
	Max int32
}

type getSaslRequest struct {
	Token []byte
}

type pingRequest struct{}
type pingResponse struct{}

type setAclRequest struct {
	Path    string
	Acl     []ACL
	Version int32
}

type setAclResponse statResponse

type SetDataRequest struct {
	Path    string
	Data    []byte
	Version int32
}

type setDataResponse statResponse

type setMaxChildren struct {
	Path string
	Max  int32
}

type setSaslRequest struct {
	Token string
}

type setSaslResponse struct {
	Token string
}

type setWatchesRequest struct {
	RelativeZxid               int64
	DataWatches                []string
	ExistWatches               []string
	ChildWatches               []string
	PersistentWatches          []string
	PersistentRecursiveWatches []string
}

type setWatchesResponse struct{}

type syncRequest pathRequest
type syncResponse pathResponse

type setAuthRequest auth
type setAuthResponse struct{}

type multiRequestOp struct {
	Header multiHeader
	Op     interface{}
}
type multiRequest struct {
	Ops []multiRequestOp
}
type multiResponseOp struct {
	Header multiHeader
	String string
	Stat   *Stat
	Err    ErrCode
}
type multiResponse struct {
	Ops []multiResponseOp
}
type MultiReadResponse struct {
	getDataResponse
	getChildrenResponse
	Err error
}
type multiReadResponse struct {
	OpResults []MultiReadResponse
}

// zk version 3.5 reconfig API
type reconfigRequest struct {
	JoiningServers []byte
	LeavingServers []byte
	NewMembers     []byte
	// curConfigId version of the current configuration
	// optional - causes reconfiguration to return an error if configuration is no longer current
	CurConfigId int64
}

type reconfigReponse getDataResponse

type addWatchRequest struct {
	Path string
	Mode AddWatchMode
}

type addWatchResponse struct{}

type checkWatchesRequest struct {
	Path string
	Type WatcherType
}

type checkWatchesResponse struct{}

func (r *multiRequest) Encode(buf []byte) (int, error) {
	total := 0
	for _, op := range r.Ops {
		op.Header.Done = false
		n, err := encodePacketValue(buf[total:], reflect.ValueOf(op))
		if err != nil {
			return total, err
		}
		total += n
	}
	n, err := encodePacketValue(buf[total:], reflect.ValueOf(multiHeader{Type: -1, Done: true, Err: -1}))
	if err != nil {
		return total, err
	}
	total += n

	return total, nil
}

func (r *multiRequest) Decode(buf []byte) (int, error) {
	r.Ops = make([]multiRequestOp, 0)
	total := 0
	for {
		header := &multiHeader{}
		n, err := decodePacketValue(buf[total:], reflect.ValueOf(header))
		if err != nil {
			return total, err
		}
		total += n
		if header.Done {
			break
		}

		req := requestStructForOp(header.Type)
		if req == nil {
			return total, ErrAPIError
		}
		n, err = decodePacketValue(buf[total:], reflect.ValueOf(req))
		if err != nil {
			return total, err
		}
		total += n
		r.Ops = append(r.Ops, multiRequestOp{*header, req})
	}
	return total, nil
}

func (r *multiResponse) Decode(buf []byte) (int, error) {
	var multiErr error

	r.Ops = make([]multiResponseOp, 0)
	total := 0
	for {
		header := &multiHeader{}
		n, err := decodePacketValue(buf[total:], reflect.ValueOf(header))
		if err != nil {
			return total, err
		}
		total += n
		if header.Done {
			break
		}

		res := multiResponseOp{Header: *header}
		var w reflect.Value
		switch header.Type {
		default:
			return total, ErrAPIError
		case opError:
			w = reflect.ValueOf(&res.Err)
		case opCreate:
			w = reflect.ValueOf(&res.String)
		case opSetData:
			res.Stat = new(Stat)
			w = reflect.ValueOf(res.Stat)
		case opCheck, opDelete:
		}
		if w.IsValid() {
			n, err := decodePacketValue(buf[total:], w)
			if err != nil {
				return total, err
			}
			total += n
		}
		r.Ops = append(r.Ops, res)
		if multiErr == nil && res.Err != errOk {
			// Use the first error as the error returned from Multi().
			multiErr = res.Err.toError()
		}
	}
	return total, multiErr
}

func (r *multiReadResponse) Decode(buf []byte) (total int, multiErr error) {
	for {
		header := &multiHeader{}
		n, err := decodePacketValue(buf[total:], reflect.ValueOf(header))
		if err != nil {
			return total, err
		}
		total += n
		if header.Done {
			break
		}

		var res MultiReadResponse
		var errCode ErrCode
		var w reflect.Value
		switch header.Type {
		case opGetData:
			w = reflect.ValueOf(&res.getDataResponse)
		case opGetChildren:
			w = reflect.ValueOf(&res.getChildrenResponse)
		case opError:
			w = reflect.ValueOf(&errCode)
		default:
			return total, ErrAPIError
		}

		n, err = decodePacketValue(buf[total:], w)
		if err != nil {
			return total, err
		}
		total += n

		if errCode != errOk {
			res.Err = errCode.toError()
		}

		r.OpResults = append(r.OpResults, res)
	}

	return total, nil
}

type watcherEvent struct {
	Type  EventType
	State State
	Path  string
}

type decoder interface {
	Decode(buf []byte) (int, error)
}

type encoder interface {
	Encode(buf []byte) (int, error)
}

func decodePacket(buf []byte, st interface{}) (n int, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(runtime.Error); ok && strings.HasPrefix(e.Error(), "runtime error: slice bounds out of range") {
				err = ErrShortBuffer
			} else {
				panic(r)
			}
		}
	}()

	v := reflect.ValueOf(st)
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return 0, ErrPtrExpected
	}
	return decodePacketValue(buf, v)
}

func decodePacketValue(buf []byte, v reflect.Value) (int, error) {
	rv := v
	kind := v.Kind()
	if kind == reflect.Ptr {
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		v = v.Elem()
		kind = v.Kind()
	}

	n := 0
	switch kind {
	default:
		return n, ErrUnhandledFieldType
	case reflect.Struct:
		if de, ok := rv.Interface().(decoder); ok {
			return de.Decode(buf)
		} else if de, ok := v.Interface().(decoder); ok {
			return de.Decode(buf)
		} else {
			for i := 0; i < v.NumField(); i++ {
				field := v.Field(i)
				n2, err := decodePacketValue(buf[n:], field)
				n += n2
				if err != nil {
					return n, err
				}
			}
		}
	case reflect.Bool:
		v.SetBool(buf[n] != 0)
		n++
	case reflect.Int32:
		v.SetInt(int64(binary.BigEndian.Uint32(buf[n : n+4])))
		n += 4
	case reflect.Int64:
		v.SetInt(int64(binary.BigEndian.Uint64(buf[n : n+8])))
		n += 8
	case reflect.String:
		ln := int(binary.BigEndian.Uint32(buf[n : n+4]))
		v.SetString(string(buf[n+4 : n+4+ln]))
		n += 4 + ln
	case reflect.Slice:
		switch v.Type().Elem().Kind() {
		default:
			count := int(binary.BigEndian.Uint32(buf[n : n+4]))
			n += 4
			values := reflect.MakeSlice(v.Type(), count, count)
			v.Set(values)
			for i := 0; i < count; i++ {
				n2, err := decodePacketValue(buf[n:], values.Index(i))
				n += n2
				if err != nil {
					return n, err
				}
			}
		case reflect.Uint8:
			ln := int(int32(binary.BigEndian.Uint32(buf[n : n+4])))
			if ln < 0 {
				n += 4
				v.SetBytes(nil)
			} else {
				bytes := make([]byte, ln)
				copy(bytes, buf[n+4:n+4+ln])
				v.SetBytes(bytes)
				n += 4 + ln
			}
		}
	}
	return n, nil
}

func encodePacket(buf []byte, st interface{}) (n int, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(runtime.Error); ok && strings.HasPrefix(e.Error(), "runtime error: slice bounds out of range") {
				err = ErrShortBuffer
			} else {
				panic(r)
			}
		}
	}()

	v := reflect.ValueOf(st)
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return 0, ErrPtrExpected
	}
	return encodePacketValue(buf, v)
}

func encodePacketValue(buf []byte, v reflect.Value) (int, error) {
	rv := v
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		v = v.Elem()
	}

	n := 0
	switch v.Kind() {
	default:
		return n, ErrUnhandledFieldType
	case reflect.Struct:
		if en, ok := rv.Interface().(encoder); ok {
			return en.Encode(buf)
		} else if en, ok := v.Interface().(encoder); ok {
			return en.Encode(buf)
		} else {
			for i := 0; i < v.NumField(); i++ {
				field := v.Field(i)
				n2, err := encodePacketValue(buf[n:], field)
				n += n2
				if err != nil {
					return n, err
				}
			}
		}
	case reflect.Bool:
		if v.Bool() {
			buf[n] = 1
		} else {
			buf[n] = 0
		}
		n++
	case reflect.Int32:
		binary.BigEndian.PutUint32(buf[n:n+4], uint32(v.Int()))
		n += 4
	case reflect.Int64:
		binary.BigEndian.PutUint64(buf[n:n+8], uint64(v.Int()))
		n += 8
	case reflect.String:
		str := v.String()
		binary.BigEndian.PutUint32(buf[n:n+4], uint32(len(str)))
		copy(buf[n+4:n+4+len(str)], []byte(str))
		n += 4 + len(str)
	case reflect.Slice:
		switch v.Type().Elem().Kind() {
		default:
			count := v.Len()
			startN := n
			n += 4
			for i := 0; i < count; i++ {
				n2, err := encodePacketValue(buf[n:], v.Index(i))
				n += n2
				if err != nil {
					return n, err
				}
			}
			binary.BigEndian.PutUint32(buf[startN:startN+4], uint32(count))
		case reflect.Uint8:
			if v.IsNil() {
				binary.BigEndian.PutUint32(buf[n:n+4], uint32(0xffffffff))
				n += 4
			} else {
				bytes := v.Bytes()
				binary.BigEndian.PutUint32(buf[n:n+4], uint32(len(bytes)))
				copy(buf[n+4:n+4+len(bytes)], bytes)
				n += 4 + len(bytes)
			}
		}
	}
	return n, nil
}

func requestStructForOp(op int32) interface{} {
	switch op {
	case opClose:
		return &closeRequest{}
	case opCreate, opCreate2:
		return &CreateRequest{}
	case opCreateContainer:
		return &CreateContainerRequest{}
	case opCreateTTL:
		return &CreateTTLRequest{}
	case opDelete:
		return &DeleteRequest{}
	case opExists:
		return &existsRequest{}
	case opGetAcl:
		return &getAclRequest{}
	case opGetChildren:
		return &getChildrenRequest{}
	case opGetChildren2:
		return &getChildren2Request{}
	case opGetData:
		return &getDataRequest{}
	case opPing:
		return &pingRequest{}
	case opSetAcl:
		return &setAclRequest{}
	case opSetData:
		return &SetDataRequest{}
	case opSetWatches, opSetWatches2:
		return &setWatchesRequest{}
	case opSync:
		return &syncRequest{}
	case opSetAuth:
		return &setAuthRequest{}
	case opCheck:
		return &CheckVersionRequest{}
	case opMulti:
		return &multiRequest{}
	case opReconfig:
		return &reconfigRequest{}
	case opAddWatch:
		return &addWatchRequest{}
	}
	return nil
}
