// Package detector contains implementation of the DNS tunneling detection
// framework.
//
// TODO: Extend.
package detector

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"

	"github.com/masterkusok/dns-tunnel-detector/internal/errors"
	"github.com/masterkusok/dns-tunnel-detector/vault"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// Context contains all the necessary data for tunneling detection.  Context
// must not be modified in pipeline jobs.
type Context struct {
	// Request represents the base DNS request, which is being filtered.
	Request *dns.Msg

	// ClientAddr is the client's IP.
	ClientAddr netip.Addr
}

// Status is a status of processed DNS query.  Possible values are:
//
// - [StatusOk]
// - [StatusUndefined]
// - [StatusDetected]
type Status uint8

// Possible detection result statuses.
//
// TODO: Extend.
const (
	StatusUndefined = iota
	StatusOk
	StatusDetected
)

// Result is the result of the tunneling detection.
type Result struct {
	Status Status
}

// Job represents single job of the tunneling detection pipeline.
type Job interface {
	Process(ctx context.Context, dnsCtx *Context) (res *Result, err error)
}

// Config is the configuration structure for [Detector].
type Config struct {
	// Logger is used for logging detector operations.  It must not be nil.
	Logger *slog.Logger

	// Jobs are used for building DNS request proccessing pipeline.  They will
	// be executed for every call, keeping the original order.
	Jobs []Job

	// Vault is used for caching detection retults.  It must not be nil.
	Vault vault.Interface
}

// Detector is used for detecting DNS tunnels.
type Detector struct {
	logger *slog.Logger
	jobs   []Job
	vault  vault.Interface
}

// New returns properly initialized *Detector.  conf must be non-nil and valid.
func New(conf *Config) (d *Detector) {
	return &Detector{
		logger: conf.Logger,
		jobs:   conf.Jobs,
		vault:  conf.Vault,
	}
}

// Detect executes detecting pipeline for given context.
func (d *Detector) Detect(ctx context.Context, dnsCtx *Context) (res *Result, err error) {
	ok, err := d.vault.CheckClientIP(ctx, dnsCtx.ClientAddr)
	if err != nil {
		return nil, fmt.Errorf("check client ip in vault: %w", err)
	}

	if ok {
		return &Result{
			Status: StatusDetected,
		}, nil
	}

	etlds := make([]string, 0, len(dnsCtx.Request.Question))
	for _, q := range dnsCtx.Request.Question {
		domain := strings.TrimSuffix(q.Name, ".")

		etld, err := publicsuffix.EffectiveTLDPlusOne(domain)
		if err != nil {
			return nil, fmt.Errorf("extracting etld: %w", err)
		}

		etlds = append(etlds, etld)
		ok, err = d.vault.CheckETLD(ctx, etld)
		if err != nil {
			return nil, fmt.Errorf("check vault etld: %s: %w", etld, err)
		}

		if !ok {
			continue
		}

		return &Result{
			Status: StatusDetected,
		}, nil
	}

	res, err = d.detectAsync(ctx, dnsCtx)
	if err != nil {
		return nil, err
	}

	if res.Status != StatusDetected {
		return res, nil
	}

	err = d.vault.AddClientIP(ctx, dnsCtx.ClientAddr)
	if err != nil {
		d.logger.ErrorContext(ctx, "populating client ip cache", "error", err)
	}

	for _, etld := range etlds {
		err = d.vault.AddETLD(ctx, etld)
		if err != nil {
			d.logger.ErrorContext(ctx, "populating etld cache", "error", err, "etld", etld)
		}
	}

	return res, nil
}

// result is the result of implementing single
type result struct {
	res *Result
	err error
}

// detectAsync runs detection pipeline in concurrent mode.  Each job is
// performed in a separate goroutine.  dnsCtx must not be nil.
func (d *Detector) detectAsync(ctx context.Context, dnsCtx *Context) (res *Result, err error) {
	jobsNum := len(d.jobs)

	results := make(chan *result, jobsNum)

	// NOTE: errgroup.Group should not be used there, because we don't want
	// to wait all the goroutines to complete if some task finished with error.
	wg := &sync.WaitGroup{}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, j := range d.jobs {
		wg.Go(func() {
			jobRes, jobErr := j.Process(ctx, dnsCtx)
			results <- &result{
				res: jobRes,
				err: jobErr,
			}
		})
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		if r.err != nil || r.res.Status != StatusOk {
			res = &Result{}
			if r.err != nil {
				res.Status = StatusUndefined
			} else {
				res = r.res
			}

			return res, errors.Annotate(r.err, "executing jobs async: %w")
		}
	}

	return &Result{
		Status: StatusOk,
	}, nil
}
