package main

import (
	"context"
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

	// Walk breadth-first.
	nodes, walkErr := c.Walker("/foo", zk.BreadthFirstOrder).All(ctx)
	for p, stat := range nodes {
		slog.Info("visited node", "path", p, "version", stat.Version)
	}
	if err = walkErr(); err != nil {
		panic(err)
	}

	// Walk depth-first.
	nodes, walkErr = c.Walker("/foo", zk.DepthFirstOrder).All(ctx)
	for p := range nodes {
		slog.Info("visited node", "path", p)
	}
	if err = walkErr(); err != nil {
		panic(err)
	}
}
