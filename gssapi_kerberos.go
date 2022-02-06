package zk

import (
        "context"
        "encoding/binary"
        "fmt"
        "strings"

        "github.com/jcmturner/gofork/encoding/asn1"
        "github.com/jcmturner/gokrb5/v8/asn1tools"
        "github.com/jcmturner/gokrb5/v8/client"
        "github.com/jcmturner/gokrb5/v8/config"
        "github.com/jcmturner/gokrb5/v8/gssapi"
        "github.com/jcmturner/gokrb5/v8/iana/chksumtype"
        "github.com/jcmturner/gokrb5/v8/iana/keyusage"
        "github.com/jcmturner/gokrb5/v8/keytab"
        "github.com/jcmturner/gokrb5/v8/messages"
        "github.com/jcmturner/gokrb5/v8/types"
        log "github.com/sirupsen/logrus"
)

const (
        TOK_ID_KRB_AP_REQ   = 256
        GSS_API_GENERIC_TAG = 0x60
        GSS_API_INITIAL     = 1
        GSS_API_VERIFY      = 2
        GSS_API_FINISH      = 3
)

type GSSAPIKerberosAuth struct {
        Config *KRBConfig
        ticket messages.Ticket
        encKey types.EncryptionKey
        krbCli KerberosClient
        step   int
}

type KerberosGoKrb5Client struct {
        client.Client
}

func (c *KerberosGoKrb5Client) Domain() string {
        return c.Credentials.Domain()
}

func (c *KerberosGoKrb5Client) CName() types.PrincipalName {
        return c.Credentials.CName()
}

// NewKerberosClient creates kerberos client used to obtain TGT and TGS tokens.
// It uses pure go Kerberos 5 solution (RFC-4121 and RFC-4120).
// uses gokrb5 library underlying which is a pure go kerberos client with some GSS-API capabilities.
func NewKerberosClient(cfg *KRBConfig) (KerberosClient, error) {
        if cfg == nil {
                return nil, fmt.Errorf("kerberos config is nil")
        }
        if kcfg, err := config.Load(cfg.KrbCfgPath); err != nil {
                return nil, err
        } else {
                return createClient(cfg, kcfg)
        }
}

func createClient(cfg *KRBConfig, kcfg *config.Config) (KerberosClient, error) {
        if cfg.KeytabPath != "" {
                kt, err := keytab.Load(cfg.KeytabPath)
                if err != nil {
                        return nil, err
                }
                return &KerberosGoKrb5Client{*client.NewWithKeytab(cfg.Username, cfg.Realm, kt, kcfg, client.DisablePAFXFAST(cfg.PAFXFAST))}, nil
        } else {
                return &KerberosGoKrb5Client{*client.NewWithPassword(cfg.Username, cfg.Realm, cfg.Password, kcfg, client.DisablePAFXFAST(cfg.PAFXFAST))}, nil
        }
}

type KerberosClient interface {
        Login() error
        GetServiceTicket(spn string) (messages.Ticket, types.EncryptionKey, error)
        Domain() string
        CName() types.PrincipalName
        Destroy()
}

func (krbAuth *GSSAPIKerberosAuth) newAuthenticatorChecksum() []byte {
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
func (krbAuth *GSSAPIKerberosAuth) createKrb5Token(
        domain string, cname types.PrincipalName,
        ticket messages.Ticket,
        sessionKey types.EncryptionKey) ([]byte, error) {
        auth, err := types.NewAuthenticator(domain, cname)
        if err != nil {
                return nil, err
        }
        auth.Cksum = types.Checksum{
                CksumType: chksumtype.GSSAPI,
                Checksum:  krbAuth.newAuthenticatorChecksum(),
        }
        APReq, err := messages.NewAPReq(
                ticket,
                sessionKey,
                auth,
        )
        if err != nil {
                return nil, err
        }
        aprBytes := make([]byte, 2)
        binary.BigEndian.PutUint16(aprBytes, TOK_ID_KRB_AP_REQ)
        tb, err := APReq.Marshal()
        if err != nil {
                return nil, err
        }
        aprBytes = append(aprBytes, tb...)
        return aprBytes, nil
}

/*
*
*       Append the GSS-API header to the payload, conforming to RFC-2743
*       Section 3.1, Mechanism-Independent Token Format
*
*       https://tools.ietf.org/html/rfc2743#page-81
*
*       GSSAPIHeader + <specific mechanism payload>
*
 */
func (krbAuth *GSSAPIKerberosAuth) appendGSSAPIHeader(payload []byte) ([]byte, error) {
        oidBytes, err := asn1.Marshal(gssapi.OIDKRB5.OID())
        if err != nil {
                return nil, err
        }
        tkoLengthBytes := asn1tools.MarshalLengthBytes(len(oidBytes) + len(payload))
        GSSHeader := append([]byte{GSS_API_GENERIC_TAG}, tkoLengthBytes...)
        GSSHeader = append(GSSHeader, oidBytes...)
        GSSPackage := append(GSSHeader, payload...)
        return GSSPackage, nil
}

func (krbAuth *GSSAPIKerberosAuth) initSecContext(bytes []byte) ([]byte, error) {
        switch krbAuth.step {
        case GSS_API_INITIAL:
                aprBytes, err := krbAuth.createKrb5Token(
                        krbAuth.krbCli.Domain(),
                        krbAuth.krbCli.CName(),
                        krbAuth.ticket,
                        krbAuth.encKey)
                if err != nil {
                        return nil, err
                }
                krbAuth.step = GSS_API_VERIFY
                return krbAuth.appendGSSAPIHeader(aprBytes)
        case GSS_API_VERIFY:
                wrapTokenReq := gssapi.WrapToken{}
                if err := wrapTokenReq.Unmarshal(bytes, true); err != nil {
                        return nil, err
                }
                // Validate response.
                isValid, err := wrapTokenReq.Verify(krbAuth.encKey, keyusage.GSSAPI_ACCEPTOR_SEAL)
                if !isValid {
                        return nil, err
                }

                wrapTokenResponse, err := gssapi.NewInitiatorWrapToken(wrapTokenReq.Payload, krbAuth.encKey)
                if err != nil {
                        return nil, err
                }
                krbAuth.step = GSS_API_FINISH
                return wrapTokenResponse.Marshal()
        }
        return nil, nil
}

/* This does the handshake for authorization */
func (krbAuth *GSSAPIKerberosAuth) Authorize(ctx context.Context, zkConn *Conn) error {
        // kerberos client login for TGT token
        if err := krbAuth.krbCli.Login(); err != nil {
                log.Fatalf("failed to login with kerberos (kinit), err: %+v", err.Error())
                return fmt.Errorf("failed to login with kerberos (kinit), err: %+v", err.Error())
        }

        // Construct SPN using serviceName and host
        // SPN format: <SERVICE>/<FQDN>
        spn := fmt.Sprintf("%s/%s", krbAuth.Config.ServiceName, strings.SplitN(zkConn.hostname, ":", 2)[0])
        ticket, encKey, err := krbAuth.krbCli.GetServiceTicket(spn)
        if err != nil {
                return err
        }
        krbAuth.ticket = ticket
        krbAuth.encKey = encKey
        krbAuth.step = GSS_API_INITIAL
        var recvBytes []byte = nil
        var packBytes []byte = nil
        defer krbAuth.krbCli.Destroy()
        for {
                if packBytes, err = krbAuth.initSecContext(recvBytes); err != nil {
                        log.Errorf("Error while performing GSSAPI Kerberos Authentication: %s, krbAuth: %+v, in initSecContext", err.Error(), krbAuth)
                        return err
                }
                var res = &setSaslResponse{}
                if _, err = zkConn.sendRequestEx(ctx, opSetSASL, &getSaslRequest{packBytes}, res, nil); err != nil {
                        log.Errorf("failed to handshake with kerberos, krbAuth: %+v, err: %s", krbAuth, err.Error())
                        return fmt.Errorf("failed to handshake with kerberos, krbAuth: %+v, err: %s", krbAuth, err.Error())
                }
                if krbAuth.step == GSS_API_VERIFY {
                        recvBytes = []byte(res.Token)
                } else if krbAuth.step == GSS_API_FINISH {
                        return nil
                }
        }
}
