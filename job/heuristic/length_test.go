package heuristic_test

import (
	"testing"

	detector "github.com/masterkusok/dns-tunnel-detector"
	"github.com/masterkusok/dns-tunnel-detector/job/heuristic"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testDomain is a common domain for tests.
const testDomain = "example.test"

func TestLength(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		domainLen    uint8
		subdomainLen uint8
		wantStatus   detector.Status
	}{{
		name:         "valid_len",
		domainLen:    100,
		subdomainLen: 100,
		wantStatus:   detector.StatusOk,
	}, {
		name:         "domain_len",
		domainLen:    5,
		subdomainLen: 100,
		wantStatus:   detector.StatusDetected,
	}, {
		name:         "subdomain_len",
		domainLen:    100,
		subdomainLen: 5,
		wantStatus:   detector.StatusDetected,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := &dns.Msg{
				Question: []dns.Question{{
					Name:   testDomain,
					Qtype:  dns.TypeA,
					Qclass: dns.ClassINET,
				}},
			}

			l := heuristic.NewLength(&heuristic.LengthConfig{
				AllowedDomainLength:    tc.domainLen,
				AllowedSubdomainLength: tc.subdomainLen,
			})

			res, err := l.Process(t.Context(), &detector.Context{Request: req})
			require.NoError(t, err)

			assert.Equal(t, tc.wantStatus, res.Status)
		})
	}
}
