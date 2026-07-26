package statistic

import (
	"context"
	"fmt"
	"strings"

	detector "github.com/masterkusok/dns-tunnel-detector"
	"golang.org/x/net/publicsuffix"
)

// DefaultMaxCardinality is a default value for
// [SubdomainCardinalityConfig.MaxCardinality].
const DefaultMaxCardinality int64 = 1000

// SubdomainCardinalityConfig is a configuration structure for
// [*SubdomainCardinality].
type SubdomainCardinalityConfig struct {
	// Counter is used for counting subdomain cardinality.  It must not be nil.
	Counter        CardinalityCounter
	MaxCardinality int64
}

// SubdomainCardinality is a job that determines DNS tunnels based on subdomain
// cardinality.
type SubdomainCardinality struct {
	counter        CardinalityCounter
	maxCardinality int64
}

// NewSubdomainCardinality returns properly initialized *SubdomainCardinality.
// conf must be non nil and valid.
func NewSubdomainCardinality(conf *SubdomainCardinalityConfig) (c *SubdomainCardinality) {
	return &SubdomainCardinality{
		counter:        conf.Counter,
		maxCardinality: conf.MaxCardinality,
	}
}

// Process implements the [detector.Job] interface for *SubdomainCardinality.
// dnsCtx must not be nil.  It is safe for concurrent use.  err is always nil.
func (e *SubdomainCardinality) Process(
	_ context.Context,
	dnsCtx *detector.Context,
) (res *detector.Result, err error) {
	msg := dnsCtx.Request

	for _, q := range msg.Question {
		domain := q.Name

		tld, err := publicsuffix.EffectiveTLDPlusOne(domain)
		if err != nil {
			return nil, fmt.Errorf("extracting tld: %w", err)
		}

		subdomain := strings.TrimSuffix(domain, tld)
		e.counter.Add(tld, subdomain)

		if e.counter.Count(domain) > e.maxCardinality {
			return &detector.Result{
				Status: detector.StatusDetected,
			}, nil
		}
	}

	return &detector.Result{
		Status: detector.StatusOk,
	}, nil
}
