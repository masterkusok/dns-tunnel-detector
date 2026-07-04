package detector_test

import (
	"context"
	"testing"

	detector "github.com/masterkusok/dns-tunnel-detector"
	"github.com/masterkusok/dns-tunnel-detector/internal/detectortest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetector_Process(t *testing.T) {
	t.Parallel()

	const (
		testTunnelDomain  = "tunnel.example"
		testSuccessDomain = "test.example"
		testErrorDomain   = "error.example"
	)

	job := &detectortest.Job{
		OnProcess: func(
			_ context.Context,
			dnsCtx *detector.Context,
		) (res *detector.Result, err error) {
			switch dnsCtx.Request.Question[0].Name {
			case testTunnelDomain:
				return &detector.Result{Status: detector.StatusDetected}, nil
			case testSuccessDomain:
				return &detector.Result{Status: detector.StatusOk}, nil
			case testErrorDomain:
				return nil, assert.AnError
			default:
				panic("unexpected domain")
			}
		},
	}

	d := detector.New(&detector.Config{
		Jobs: []detector.Job{
			job,
		},
	})

	testCases := []struct {
		name       string
		reqDomain  string
		wantStatus detector.Status
		wantErr    error
	}{{
		name:       "ok",
		reqDomain:  testSuccessDomain,
		wantStatus: detector.StatusOk,
		wantErr:    nil,
	}, {
		name:       "tunnel",
		reqDomain:  testTunnelDomain,
		wantStatus: detector.StatusDetected,
		wantErr:    nil,
	}, {
		name:       "error",
		reqDomain:  testErrorDomain,
		wantStatus: 0,
		wantErr:    assert.AnError,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dnsCtx := &detector.Context{
				Request: &dns.Msg{
					Question: []dns.Question{{
						Name: tc.reqDomain,
					}},
				},
			}

			res, err := d.Detect(t.Context(), dnsCtx)
			if err != nil {
				require.ErrorIs(t, err, tc.wantErr)

				return
			}

			require.NoError(t, err)

			assert.Equal(t, tc.wantStatus, res.Status)
		})
	}
}
