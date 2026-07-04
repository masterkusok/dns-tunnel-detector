package heuristic

import (
	"cmp"
	"context"

	detector "github.com/masterkusok/dns-tunnel-detector"
	"github.com/masterkusok/dns-tunnel-detector/internal/math"
)

// DefaultThreshold is the default entropy threshold.
const DefaultThreshold = 4.5

// Entropy is a job that determines DNS-tunneling based on hostname entropy.
type Entropy struct {
	threshold float64
}

// NewEntropy returns properly initialized *Entropy.
func NewEntropy(threshold float64) (e *Entropy) {
	return &Entropy{
		threshold: cmp.Or(threshold, float64(DefaultThreshold)),
	}
}

// Process implements the [detector.Job] interface for *Entropy.  dnsCtx must not
// be nil.  It is safe for concurrent use.  err is always nil.
func (e *Entropy) Process(
	_ context.Context,
	dnsCtx *detector.Context,
) (res *detector.Result, err error) {
	msg := dnsCtx.Request

	for _, q := range msg.Question {
		if math.CalculateShannonEntropy(q.Name) > e.threshold {
			return &detector.Result{
				Status: detector.StatusDetected,
			}, nil
		}
	}

	return &detector.Result{
		Status: detector.StatusOk,
	}, nil
}
