package zk

import (
	"log"
	"os"
	"testing"

	"github.com/jcmturner/krb5test"
)

func TestSASLAuth(t *testing.T) {
	// start mock kdc
	krb5test.ServerAddr = "localhost:88"
	krb5test.ServerDomain = "test.realm.com"
	krb5test.ServerRealm = "TEST.COM"
	var principals = map[string][]string{
		"zookeeper/localhost": {},
		"test":                {"test"},
	}
	var err error
	kdcServer, err = krb5test.NewKDC(principals, log.New(os.Stderr, "KDC Test Server: ", log.LstdFlags))
	if err != nil {
		panic(err)
	}
	kdcServer.Start()
	defer kdcServer.Close()
	tc, err := StartTestCluster(t, 3, nil, logWriter{t: t, p: "[ZKERR] "})
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Stop()
	zk, _, err := tc.ConnectAll()
	if err != nil {
		t.Fatalf("Connect returned error: %+v", err)
	}
	defer zk.Close()
	path := "/gozk-test"

	if err := zk.Delete(path, -1); err != nil && err != ErrNoNode {
		t.Fatalf("Delete returned error: %+v", err)
	}
	if p, err := zk.Create(path, []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
		t.Fatalf("Create returned error: %+v", err)
	} else if p != path {
		t.Fatalf("Create returned different path '%s' != '%s'", p, path)
	}
	if data, stat, err := zk.Get(path); err != nil {
		t.Fatalf("Get returned error: %+v", err)
	} else if stat == nil {
		t.Fatal("Get returned nil stat")
	} else if len(data) < 4 {
		t.Fatal("Get returned wrong size data")
	}
}
