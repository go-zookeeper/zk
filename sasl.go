package zk

import (
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
	GSSAPI_INITIAL     = 1
	GSSAPI_VERIFY      = 2
	GSSAPI_FINISH      = 3
)

type KerberosAuth struct {
	Config *KerberosConfig
	ticket messages.Ticket  // client to service ticket
	encKey types.EncryptionKey // service session key
	step   int
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

func (k *KerberosAuth) newAuthenticatorChecksum() []byte {
	a := make([]byte, 24)
	flags := []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}
	binary.LittleEndian.PutUint32(a[:4], 16)
	for _, i := range flags {
		f := binary.LittleEndian.Uint32(a[20:24])
		f |= uint32(i)
		binary.LittleEndian.PutUint32(a[20:24], f)
	}
	return a
}

/*
*
* Construct Kerberos AP_REQ package, conforming to RFC-4120
* https://tools.ietf.org/html/rfc4120#page-84
*
 */
func (k *KerberosAuth) createKrb5Token(
	domain string, cname types.PrincipalName,
	ticket messages.Ticket, encKey types.EncryptionKey) ([]byte, error) {
	auth, err := types.NewAuthenticator(domain, cname)
	if err != nil {
		return nil, err
	}
	auth.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  k.newAuthenticatorChecksum(),
	}
	if APReq, err := messages.NewAPReq(ticket, encKey, auth); err != nil {
		return nil, err
	} else {
		aprBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(aprBytes, TOK_ID_KRB_AP_REQ)
		tb, err := APReq.Marshal()
		if err != nil {
			return nil, err
		}
		aprBytes = append(aprBytes, tb...)
		return aprBytes, nil
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
func (k *KerberosAuth) appendGSSAPIHeader(payload []byte) ([]byte, error) {
	oidBytes, err := asn1.Marshal(gssapi.OIDKRB5.OID())
	if err != nil {
		return nil, err
	}
	tkoLengthBytes := asn1tools.MarshalLengthBytes(len(oidBytes) + len(payload))
	gssapiHeader := append([]byte{GSSAPI_GENERIC_TAG}, tkoLengthBytes...)
	gssapiHeader = append(gssapiHeader, oidBytes...)
	GSSPackage := append(gssapiHeader, payload...)
	return GSSPackage, nil
}

func (k *KerberosAuth) initSecContext(bytes []byte, krbCli *krb5client.Client) ([]byte, error) {
	switch k.step {
	case GSSAPI_INITIAL:
		krb5Token, err := k.createKrb5Token(
			krbCli.Credentials.Domain(),
			krbCli.Credentials.CName(),
			k.ticket, k.encKey)
		if err != nil {
			return nil, err
		}
		k.step = GSSAPI_VERIFY
		return k.appendGSSAPIHeader(krb5Token)
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
func (k *KerberosAuth) Authorize(zkConn *Conn) error {
	// create kerberos client
	krbCli, err := newKerberosClient(zkConn.saslConfig.KerberosConfig)
	if err != nil {
		return fmt.Errorf("fail to create kerberos client, err: %s", err)
	}
	// kerberos client login for TGT token
	if err = krbCli.Login(); err != nil {
		return fmt.Errorf("kerberos client fail to login, err: %s", err)
	}

	// construct SPN using serviceName and host, format: zookeeper/host
	spn := fmt.Sprintf("%s/%s", k.Config.ServiceName, strings.SplitN(zkConn.hostname, ":", 2)[0])

	// kerberos client obtain TGS token
	if k.ticket, k.encKey, err = krbCli.GetServiceTicket(spn); err != nil {
		return fmt.Errorf("kerberos client fail to get service ticket, err: %s", err)
	}
	k.step = GSSAPI_INITIAL
	var recvBytes []byte = nil
	var packBytes []byte = nil
	defer krbCli.Destroy()
	for {
		if packBytes, err = k.initSecContext(recvBytes, krbCli); err != nil {
			return fmt.Errorf("failed to init session context while performing kerberos authentication, err: %s", err)
		}
		var res = &setSaslResponse{}
		if _, err = zkConn.sendRequest(opSetAuth, &getSaslRequest{packBytes}, res, nil); err != nil {
			return fmt.Errorf("failed to handshake with kerberos, err: %s", err)
		}
		if k.step == GSSAPI_VERIFY {
			recvBytes = []byte(res.Token)
		} else if k.step == GSSAPI_FINISH {
			return nil
		}
	}
}

func writePackage(zkConn *Conn, payload []byte) error {

} 

func readPackage(zkConn *Conn) ([]byte, error) {
	
}
