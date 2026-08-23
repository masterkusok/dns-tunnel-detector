// Package handler contains the implementation of proxy handler for detecting
// dns tunnels.
package handler

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/masterkusok/dns-tunnel-detector/detector"
	"github.com/miekg/dns"
)

// Config is the configuration structure for Default.
type Config struct {
	// Logger is used for logging handler operations.
	Logger *slog.Logger

	// Detector is used for detecting dns tunnels.
	Detector *detector.Detector
}

// Default is the [proxy.Handler] implementation that analyzes traffic for dns
// tunnels.
type Default struct {
	logger   *slog.Logger
	detector *detector.Detector
}

// NewDefault returns properly initialized *Default.  conf must be non-nil and
// valid.
func NewDefault(conf *Config) (d *Default) {
	return &Default{
		logger:   conf.Logger,
		detector: conf.Detector,
	}
}

// ServeDNS implements the [proxy.DNSContext] for *PipelineHandler
func (h *Default) ServeDNS(
	ctx context.Context,
	p *proxy.Proxy,
	dctx *proxy.DNSContext,
) (err error) {
	h.logger.InfoContext(ctx, "handling request")
	defer h.logger.InfoContext(ctx, "request handled")

	dnsCtx := &detector.Context{
		Request:    dctx.Req,
		ClientAddr: dctx.Addr.Addr(),
	}

	h.logger.InfoContext(ctx, "running detector")
	res, err := h.detector.Detect(ctx, dnsCtx)
	if err != nil {
		h.logger.ErrorContext(ctx, "error while detecting tunnels", "error", err)

		return fmt.Errorf("detecting: %w", err)
	}

	h.logger.InfoContext(ctx, "detector run finished successfully", "status", res.Status)

	switch res.Status {
	case detector.StatusOk:
		return p.Resolve(ctx, dctx)
	case detector.StatusDetected:
		dctx.Res = h.blockedResponse(dctx.Req)

		return nil
	case detector.StatusUndefined:
		h.logger.WarnContext(ctx, "undefined detection status")

		// TODO: remove, consider handling another way.
		fallthrough
	default:
		panic("unknown status detection status: " + string(res.Status))
	}
}

// blockedResponse returns common response for blocked requests.
func (h *Default) blockedResponse(req *dns.Msg) (resp *dns.Msg) {
	resp = &dns.Msg{}
	resp = resp.SetReply(req)

	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   "suspicious.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: net.IP{2, 2, 2, 2},
	})

	return resp
}
