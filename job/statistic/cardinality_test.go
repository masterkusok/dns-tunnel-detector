package statistic_test

import (
	"context"
	"testing"

	detector "github.com/masterkusok/dns-tunnel-detector"
	"github.com/masterkusok/dns-tunnel-detector/internal/detectortest"
	"github.com/masterkusok/dns-tunnel-detector/job/statistic"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubdomainCardinality(t *testing.T) {
	t.Parallel()

	const testCount = 10
	counter := &detectortest.Counter{
		OnAdd: func(tld string, subdomain string) {},
		OnCount: func(tld string) (res int64) {
			return testCount
		},
	}

	testCases := []struct {
		name           string
		maxCardinality int64
		status         detector.Status
	}{{
		name:           "ok",
		maxCardinality: 100,
		status:         detector.StatusOk,
	}, {
		name:           "blocked",
		maxCardinality: 5,
		status:         detector.StatusDetected,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sc := statistic.NewSubdomainCardinality(&statistic.SubdomainCardinalityConfig{
				Counter:        counter,
				MaxCardinality: tc.maxCardinality,
			})

			req := &dns.Msg{
				Question: []dns.Question{{
					Name:   "example.com",
					Qtype:  dns.TypeA,
					Qclass: dns.ClassINET,
				}},
			}

			ctx := context.Background()
			res, err := sc.Process(ctx, &detector.Context{Request: req})
			require.NoError(t, err)

			assert.Equal(t, tc.status, res.Status)
		})
	}
}
