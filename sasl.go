package zk

import (
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Handle the SASL authentification.
const (
	zkSaslMd5Uri      = "zookeeper/zk-sasl-md5"
	zkSaslAuthQop     = "auth"
	zkSaslAuthIntQop  = "auth-int"
	zkSaslAuthConfQop = "auth-conf"
)

type setSaslResponse struct {
	Nonce     string
	Realm     string
	Charset   string
	Algorithm string
	RspAuth   string
}

func getHexMd5(s string) string {
	bs := []byte(s)
	hash := ""
	sum := md5.Sum(bs)
	for _, b := range sum {
		hash += fmt.Sprintf("%02x", b)
	}
	return hash
}

func getMd5(s string) string {
	bs := []byte(s)
	sum := md5.Sum(bs)
	return string(sum[:])
}

func doubleQuote(s string) string {
	return `"` + s + `"`
}

func rmDoubleQuote(s string) string {
	leng := len(s)
	return s[1 : leng-1]
}

func (r setSaslResponse) getUserPassword(auth []byte) (string, string) {
	userPassword := string(auth)

	split := strings.SplitN(userPassword, ":", 2)

	return split[0], split[1]
}

func (r setSaslResponse) genA1(user, password, cnonce string) string {
	hexStr := fmt.Sprintf("%s:%s:%s", user, r.Realm, password)
	hash := getMd5(hexStr)
	keyHash := fmt.Sprintf("%s:%s:%s", hash, r.Nonce, cnonce)
	return getHexMd5(keyHash)
}

func (r setSaslResponse) genChallenge(user, password, cnonce, qop string, nc int) string {

	rawA2 := fmt.Sprintf("%s:%s", "AUTHENTICATE", zkSaslMd5Uri)
	a2 := getHexMd5(rawA2)

	a1 := r.genA1(user, password, cnonce)

	rv := fmt.Sprintf("%s:%s:%08x:%s:%s:%s", a1, r.Nonce, nc, cnonce, qop, a2)

	return getHexMd5(rv)
}

// GenSaslChallenge refers to RFC2831 to generate a md5-digest challenge.
func (r setSaslResponse) GenSaslChallenge(auth []byte, cnonce string) (string, error) {

	user, password := r.getUserPassword(auth)
	if user == "" || password == "" {
		return "", errors.New("found invalid user&password")
	}

	ch := make(map[string]string, 20)

	ch["digest-uri"] = doubleQuote(zkSaslMd5Uri)

	// Only "auth" qop supports so far.
	qop := zkSaslAuthQop
	ch["qop"] = qop

	nc := 1
	ch["nc"] = fmt.Sprintf("%08x", nc)

	ch["realm"] = doubleQuote(r.Realm)
	ch["username"] = doubleQuote(user)

	// for unittest.
	if cnonce == "" {
		n, err := rand.Int(rand.Reader, big.NewInt(65535))
		if err != nil {
			return "", err
		}
		cnonce = fmt.Sprintf("%s", n)
	}
	ch["cnonce"] = doubleQuote(cnonce)
	ch["nonce"] = doubleQuote(r.Nonce)

	ch["response"] = r.genChallenge(user, password, cnonce, qop, nc)

	items := make([]string, 0, len(ch))

	for k, v := range ch {
		items = append(items, fmt.Sprintf("%s=%s", k, v))
	}

	return strings.Join(items, ","), nil
}

// Decode decodes a md5-digest ZK SASL response.
func (r *setSaslResponse) Decode(buf []byte) (int, error) {

	// Discard the first 4 bytes, they are not used here.
	// According to RFC, the payload is inform of k1=v,k2=v, some of the values maybe enclosure with double quote(").
	payload := string(buf[4:])

	splitPayload := strings.Split(payload, ",")

	if len(splitPayload) == 0 {
		return 0, errors.New("invalid sasl payload")
	}

	r.Nonce = ""
	r.Realm = ""
	r.RspAuth = ""

	for _, item := range splitPayload {
		kv := strings.SplitN(item, "=", 2)
		if len(kv) != 2 {
			return 0, errors.New("invalid sasl payload format")
		}

		key := strings.ToLower(kv[0])
		if key == "nonce" {
			r.Nonce = rmDoubleQuote(kv[1])
		} else if key == "realm" {
			r.Realm = rmDoubleQuote(kv[1])
		} else if key == "rspauth" {
			r.RspAuth = kv[1]
		}
	}

	return len(buf), nil
}
