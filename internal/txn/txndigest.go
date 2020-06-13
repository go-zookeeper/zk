// Autogenerated jute compiler
// @generated from 'jute/zookeeper.jute'

package txn // github.com/go-zookeeper/zk/internal/txn

import (
	"fmt"

	"github.com/go-zookeeper/jute/lib/go/jute"
)

type TxnDigest struct {
	Version    int32 // version
	TreeDigest int64 // treeDigest
}

func (r *TxnDigest) GetVersion() int32 {
	if r != nil {
		return r.Version
	}
	return 0
}

func (r *TxnDigest) GetTreeDigest() int64 {
	if r != nil {
		return r.TreeDigest
	}
	return 0
}

func (r *TxnDigest) Read(dec jute.Decoder) (err error) {
	if err = dec.ReadStart(); err != nil {
		return err
	}
	r.Version, err = dec.ReadInt()
	if err != nil {
		return err
	}
	r.TreeDigest, err = dec.ReadLong()
	if err != nil {
		return err
	}
	if err = dec.ReadEnd(); err != nil {
		return err
	}
	return nil
}

func (r *TxnDigest) Write(enc jute.Encoder) error {
	if err := enc.WriteStart(); err != nil {
		return err
	}
	if err := enc.WriteInt(r.Version); err != nil {
		return err
	}
	if err := enc.WriteLong(r.TreeDigest); err != nil {
		return err
	}
	if err := enc.WriteEnd(); err != nil {
		return err
	}
	return nil
}

func (r *TxnDigest) String() string {
	if r == nil {
		return "<nil>"
	}
	return fmt.Sprintf("TxnDigest(%+v)", *r)
}
