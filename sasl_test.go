package zk

import (
	"strings"
	"testing"
)

func TestDecode(t *testing.T) {

	// Response is expected.
	buf := `0000nonce="1x1",realm="2x2",rspauth="3x3"`
	resp := &setSaslResponse{}

	length, err := resp.Decode([]byte(buf))

	if err != nil || length != len(buf) {
		t.Errorf("failed to check Decode, %v", resp)
	}

	if resp.Nonce != "1x1" || resp.Realm != "2x2" {
		t.Errorf("failed to check Decode, %v", resp)
	}

	if resp.RspAuth != `"3x3"` {
		t.Errorf("failed to check Decode, %v", resp)
	}

	// Response is not expected.
	buf = `0000nonce"1x1",realm="2x2",rspauth="3x3"`
	resp = &setSaslResponse{}

	_, err = resp.Decode([]byte(buf))

	if err == nil {
		t.Errorf("failed to check abnormal Decode, %v", resp)
	}

}

func TestGenA1(t *testing.T) {
	resp := setSaslResponse{}
	resp.Realm = "test"
	resp.Nonce = "1111"

	hash := resp.genA1("super", "password", "1111")

	if hash == "" {
		t.Errorf("failed to genA1, %v", resp)
	}
}

func TestGenSaslChallenge(t *testing.T) {
	resp := setSaslResponse{}
	resp.Realm = "zk-sasl-md5"
	resp.Nonce = "qWkHmx+rW9vYQNysvUOCA3gWLks3u9cL5rc9JJFi"

	auth := "super:admin"
	hash, err := resp.GenSaslChallenge([]byte(auth), "140741146289")

	if hash == "" || err != nil {
		t.Errorf("failed to genA1, %v, error: %v", resp, err)
	}

	expect := "08125d12f8b89ca7dd8b5028b5cd7c3b"
	if !strings.Contains(hash, expect) {
		t.Errorf("failed to gen hash %s, expect %s.", hash, expect)
	}
}
