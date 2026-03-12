package main

import (
	"context"
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

	// Walk breadth-first.
	err = c.Walker("/foo", zk.BreadthFirstOrder).
		Walk(ctx, func(_ context.Context, p string, stat *zk.Stat) error {
			log.Printf("Got %s", p)
			return nil
		})
	if err != nil {
		panic(err)
	}

	// Walk depth-first.
	err = c.Walker("/foo", zk.DepthFirstOrder).
		Walk(ctx, func(_ context.Context, p string, stat *zk.Stat) error {
			log.Printf("Got %s", p)
			return nil
		})
	if err != nil {
		panic(err)
	}

	// Walk breadth-first and iterate using All.
	for p, stat := range c.Walker("/foo", zk.BreadthFirstOrder).All(ctx) {
		log.Printf("Got %s (version=%d)", p, stat.Version)
	}
}
