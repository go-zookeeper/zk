package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Shopify/zk"
)

func main() {
	c, events, err := zk.Connect([]string{"127.0.0.1:2181", "127.0.0.1:2182", "127.0.0.1:2183"}, time.Second) //*10)
	if err != nil {
		panic(err)
	}
	go func() {
		for e := range events {
			log.Printf("SessionEvent: %+v", e)
		}
		log.Printf("SessionEvent closed")
	}()

	ctx := context.Background()
	walker := c.Walker("/leaves", zk.BreadthFirstOrder)

	for {
		<-time.After(time.Second)
		var leaves []string
		err := walker.Walk(ctx, func(_ context.Context, p string, stat *zk.Stat) error {
			leaves = append(leaves, p)
			return nil
		})
		if err != nil {
			panic(err)
		}
		fmt.Printf("Got %d leaves:\n%+v\n", len(leaves), leaves)
	}
}
