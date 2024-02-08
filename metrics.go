package zk

import (
	"time"
)

type MetricReceiver interface {
	PingSent()
	PongReceived()
	RequestCompleted(duration time.Duration, err error)
}

var _ MetricReceiver = UnimplementedMetricReceiver{}

type UnimplementedMetricReceiver struct {
}

func (u UnimplementedMetricReceiver) PingSent()                             {}
func (u UnimplementedMetricReceiver) PongReceived()                         {}
func (u UnimplementedMetricReceiver) RequestCompleted(time.Duration, error) {}
