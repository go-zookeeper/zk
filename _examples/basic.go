package main

import (
	"context"
	"fmt"
	"time"

	"github.com/Shopify/zk"
)

func main() {
	c, _, err := zk.Connect([]string{"127.0.0.1:2181", "127.0.0.1:2182", "127.0.0.1:2183"}, time.Second) //*10)
	if err != nil {
		panic(err)
	}
	ch, err := c.AddWatch(context.Background(), "/", true)
	if err != nil {
		panic(err)
	}
	for e := range ch {
		fmt.Printf("%+v\n", e)
	}
}
