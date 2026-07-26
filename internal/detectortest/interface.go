package detectortest

import (
	"context"

	detector "github.com/masterkusok/dns-tunnel-detector"
	"github.com/masterkusok/dns-tunnel-detector/job/statistic"
)

// Job is the mock implementation of the [detector.Job] interface.
type Job struct {
	OnProcess func(ctx context.Context, dnsCtx *detector.Context) (res *detector.Result, err error)
}

// type check
var _ detector.Job = (*Job)(nil)

// Process implements the [detector.Job] interface for Job.
func (j *Job) Process(ctx context.Context, dnsCtx *detector.Context) (res *detector.Result, err error) {
	return j.OnProcess(ctx, dnsCtx)
}

// Counter is the mock implementation of the [statistic.CardinalityCounter].
type Counter struct {
	OnAdd   func(tld, subdomain string)
	OnCount func(tld string) (res int64)
}

// type check
var _ statistic.CardinalityCounter = (*Counter)(nil)

// Add implements the [CardinalityCounter] interface for *Counter.
func (c *Counter) Add(tld, subdomain string) {
	c.OnAdd(tld, subdomain)
}

// Count implements the [CardinalityCounter] interface for *Counter.
func (c *Counter) Count(tld string) (res int64) {
	return c.OnCount(tld)
}
