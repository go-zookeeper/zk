package zk

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	krb5client "github.com/jcmturner/gokrb5/v8/client"
	krb5config "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	krb5keytab "github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

type SASLConfig struct {
	SASLType       SASLType
	KerberosConfig *KerberosConfig
}

type KerberosConfig struct {
	KeytabPath  string // keytab file path
	KrbCfgPath  string // krb5 config file path
	Username    string
	Password    string
	Realm       string
	ServiceName string
}

const (
	TOK_ID_KRB_AP_REQ  = 256
	GSSAPI_GENERIC_TAG = 0x60
)

type GSSAPI_STEP int

const (
	GSSAPI_INITIAL GSSAPI_STEP = iota
	GSSAPI_VERIFY
	GSSAPI_FINISH
)

type KerberosAuth struct {
	Config *KerberosConfig
	ticket messages.Ticket     // client to service ticket
	encKey types.EncryptionKey // service session key
	step   GSSAPI_STEP
}

// newKerberosClient creates kerberos client used to obtain TGT and TGS tokens.
// It uses pure go Kerberos 5 solution (RFC-4121 and RFC-4120).
// uses gokrb5 library underlying which is a pure go kerberos client with some GSS-API capabilities.
func newKerberosClient(c *KerberosConfig) (*krb5client.Client, error) {
	if c == nil {
		return nil, fmt.Errorf("kerberos config is nil")
	}
	if krb5cfg, err := krb5config.Load(c.KrbCfgPath); err != nil {
		return nil, err
	} else {
		if c.KeytabPath != "" {
			if keytab, err := krb5keytab.Load(c.KeytabPath); err != nil {
				return nil, err
			} else {
				return krb5client.NewWithKeytab(c.Username, c.Realm, keytab, krb5cfg), nil
			}
		} else {
			return krb5client.NewWithPassword(c.Username, c.Realm, c.Password, krb5cfg), nil
		}
	}
}

func (k *KerberosAuth) initSecContext(bytes []byte, krbCli *krb5client.Client) ([]byte, error) {
	switch k.step {
	case GSSAPI_INITIAL:
		if krb5Token, err := createKrb5Token(
			krbCli.Credentials.Domain(),
			krbCli.Credentials.CName(),
			k.ticket, k.encKey,
		); err != nil {
			return nil, err
		} else {
			k.step = GSSAPI_VERIFY
			return appendGSSAPIHeader(krb5Token)
		}

	case GSSAPI_VERIFY:
		wrapTokenReq := gssapi.WrapToken{}
		if err := wrapTokenReq.Unmarshal(bytes, true); err != nil {
			return nil, err
		}
		// Validate response.
		isValid, err := wrapTokenReq.Verify(k.encKey, keyusage.GSSAPI_ACCEPTOR_SEAL)
		if !isValid {
			return nil, err
		}

		wrapTokenResponse, err := gssapi.NewInitiatorWrapToken(wrapTokenReq.Payload, k.encKey)
		if err != nil {
			return nil, err
		}
		k.step = GSSAPI_FINISH
		return wrapTokenResponse.Marshal()
	}
	return nil, nil
}

/* This does the handshake for authorization */
func (k *KerberosAuth) Authorize(ctx context.Context, c *Conn) error {
	// create kerberos client
	krbCli, err := newKerberosClient(c.saslConfig.KerberosConfig)
	if err != nil {
		return fmt.Errorf("failed to create kerberos client, err: %s", err)
	}
	// kerberos client login for TGT token
	if err = krbCli.Login(); err != nil {
		return fmt.Errorf("kerberos client fails to login, err: %s", err)
	}
	defer krbCli.Destroy()

	// construct SPN using serviceName and host, format: zookeeper/host
	spn := fmt.Sprintf("%s/%s", k.Config.ServiceName, strings.SplitN(c.hostname, ":", 2)[0])

	// kerberos client obtain TGS token
	if k.ticket, k.encKey, err = krbCli.GetServiceTicket(spn); err != nil {
		return fmt.Errorf("kerberos client fails to obtain service ticket, err: %s", err)
	}
	var (
		recvBytes []byte = nil
		packBytes []byte = nil
	)

	// client handshakes with zookeeper service
	k.step = GSSAPI_INITIAL
	for {
		if packBytes, err = k.initSecContext(recvBytes, krbCli); err != nil {
			c.logger.Printf("failed to init session context while performing kerberos authentication, err: %s", err)
			return err
		}

		var (
			saslReq  = &setSaslRequest{string(packBytes)}
			saslRsp  = &setSaslResponse{}
			recvChan <-chan response
		)
		if recvChan, err = c.sendRequest(opSetSASL, saslReq, saslRsp, nil); err != nil {
			c.logger.Printf("failed to send setSASL request while performing kerberos authentication, err: %s", err)
			return err
		}

		select {
		case res := <-recvChan:
			if res.err != nil {
				c.logger.Printf("failed to recv setSASL response while performing kerberos authentication, err: %s", res.err)
				return res.err
			}
		case <-c.closeChan:
			c.logger.Printf("recv closed, cancel recv setSASL response while preforming kerberos authentication")
			return nil
		case <-c.shouldQuit:
			c.logger.Printf("should quit, cancel recv setSASL response while preforming kerberos authentication")
			return nil
		case <-ctx.Done():
			c.logger.Printf("context is done while performing kerberos authentication")
			return ctx.Err()
		}

		if k.step == GSSAPI_FINISH {
			return nil
		} else if k.step == GSSAPI_VERIFY {
			recvBytes = []byte(saslRsp.Token)
		}
	}
}

/*
*
* Construct Kerberos AP_REQ package, conforming to RFC-4120
* https://tools.ietf.org/html/rfc4120#page-84
*
 */
func createKrb5Token(
	domain string, cname types.PrincipalName,
	ticket messages.Ticket, encKey types.EncryptionKey) ([]byte, error) {
	if auth, err := types.NewAuthenticator(domain, cname); err != nil {
		return nil, err
	} else {

		auth.Cksum = types.Checksum{
			CksumType: chksumtype.GSSAPI,
			Checksum:  createCheckSum(),
		}
		APReq, err := messages.NewAPReq(ticket, encKey, auth)
		if err != nil {
			return nil, err
		}
		aprBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(aprBytes, TOK_ID_KRB_AP_REQ)
		reqBytes, err := APReq.Marshal()
		if err != nil {
			return nil, err
		}
		return append(aprBytes, reqBytes...), nil
	}
}

/*
*
* Append the GSS-API header to the payload, conforming to RFC-2743
* Section 3.1, Mechanism-Independent Token Format
*
* https://tools.ietf.org/html/rfc2743#page-81
*
* GSSAPIHeader + <specific mechanism payload>
*
 */
func appendGSSAPIHeader(payload []byte) ([]byte, error) {
	oidBytes, err := asn1.Marshal(gssapi.OIDKRB5.OID())
	if err != nil {
		return nil, err
	}
	lengthBytes := asn1tools.MarshalLengthBytes(len(oidBytes) + len(payload))
	gssapiHeader := append([]byte{GSSAPI_GENERIC_TAG}, lengthBytes...)
	gssapiHeader = append(gssapiHeader, oidBytes...)
	gssapiPacket := append(gssapiHeader, payload...)
	return gssapiPacket, nil
}

func createCheckSum() []byte {
	var checkSum = make([]byte, 24)
	binary.LittleEndian.PutUint32(checkSum[:4], 16)
	for _, flag := range []uint32{
		uint32(gssapi.ContextFlagInteg),
		uint32(gssapi.ContextFlagConf),
	} {
		binary.LittleEndian.PutUint32(checkSum[20:24],
			binary.LittleEndian.Uint32(checkSum[20:24])|flag,
		)
	}
	return checkSum
}
