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
	err = c.Walker("/foo", zk.BreadthFirstOrder).
		Walk(ctx, func(_ context.Context, p string, stat *zk.Stat) error {
			slog.Info("visited node", "path", p)
			return nil
		})
	if err != nil {
		panic(err)
	}

	// Walk depth-first.
	err = c.Walker("/foo", zk.DepthFirstOrder).
		Walk(ctx, func(_ context.Context, p string, stat *zk.Stat) error {
			slog.Info("visited node", "path", p)
			return nil
		})
	if err != nil {
		panic(err)
	}

	// Walk breadth-first and iterate using All.
	for p, stat := range c.Walker("/foo", zk.BreadthFirstOrder).All(ctx) {
		slog.Info("visited node", "path", p, "version", stat.Version)
	}
}
