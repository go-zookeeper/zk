package main

import (
	"context"
	"fmt"
	"log/slog"
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
			slog.Info("session event", "event", e)
		}
		slog.Info("session event channel closed")
	}()

	ctx := context.Background()
	walker := c.Walker("/leaves", zk.BreadthFirstOrder)

	for {
		<-time.After(time.Second)
		var leaves []string
		nodes, walkErr := walker.All(ctx)
		for p := range nodes {
			leaves = append(leaves, p)
		}
		if err := walkErr(); err != nil {
			panic(err)
		}
		fmt.Printf("Got %d leaves:\n%+v\n", len(leaves), leaves)
	}
}
