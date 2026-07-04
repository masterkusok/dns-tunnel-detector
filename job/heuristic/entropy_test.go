package heuristic_test

import (
	"testing"

	detector "github.com/masterkusok/dns-tunnel-detector"
	"github.com/masterkusok/dns-tunnel-detector/job/heuristic"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEntropy(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		domain     string
		wantStatus detector.Status
	}{{
		name:       "not_detected",
		domain:     "abc.com",
		wantStatus: detector.StatusOk,
	}, {
		name: "detected",
		// Some string with obviously, high entropy
		domain:     "abdfghijklpqrsvwxyzабвгдеёжз1234.tunel.com",
		wantStatus: detector.StatusDetected,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := &dns.Msg{
				Question: []dns.Question{{
					Name:   tc.domain,
					Qtype:  dns.TypeA,
					Qclass: dns.ClassINET,
				}},
			}

			l := heuristic.NewEntropy(heuristic.DefaultThreshold)

			res, err := l.Process(t.Context(), &detector.Context{Request: req})
			require.NoError(t, err)

			assert.Equal(t, tc.wantStatus, res.Status)
		})
	}
}
