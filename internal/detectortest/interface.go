package detectortest

import (
	"context"

	detector "github.com/masterkusok/dns-tunnel-detector"
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
