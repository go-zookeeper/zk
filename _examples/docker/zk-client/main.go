package main

import (
	"log"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// connect to zk using myzkclient kerberos keytab.

	return nil
}
