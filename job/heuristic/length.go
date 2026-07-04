package heuristic

import (
	"cmp"
	"context"
	"strings"

	detector "github.com/masterkusok/dns-tunnel-detector"
	"github.com/miekg/dns"
)

const (
	// DefaultAllowedDomainLength is the default maximum allowed length for
	// domain.
	//
	// TODO: Find out, which value is logically okay.
	DefaultAllowedDomainLength = 32

	// DefaultAllowedSubdomainLength is the default maximum allowed length for
	// each subdomain.
	//
	// TODO: Find out, which value is logically okay.
	DefaultAllowedSubdomainLength = 32
)

// LengthConfig is a configuration structure for [Length].
type LengthConfig struct {
	// AllowedDomainLength defines maximum allowed length for requested domain.
	AllowedDomainLength uint8

	// AllowedSubdomainLength defines maximum allowed length for each subdomain.
	AllowedSubdomainLength uint8
}

// Length is a job that determines DNS-tunneling based on domain or subdomain
// length.
//
// TODO: implement.
type Length struct {
	domainLen    uint8
	subdomainLen uint8
}

// NewLength returns properly initialized *Length.  is conf is nil, default
// values will be used.
func NewLength(conf *LengthConfig) (l *Length) {
	conf = cmp.Or(conf)

	return &Length{
		domainLen:    cmp.Or(conf.AllowedDomainLength, uint8(DefaultAllowedDomainLength)),
		subdomainLen: cmp.Or(conf.AllowedSubdomainLength, uint8(DefaultAllowedSubdomainLength)),
	}
}

// Process implements the [detector.Job] interface for *Length.  dnsCtx must not
// be nil.  It is safe for concurrent use.  err is always nil.
func (l *Length) Process(
	_ context.Context,
	dnsCtx *detector.Context,
) (res *detector.Result, err error) {
	msg := dnsCtx.Request

	for _, q := range msg.Question {
		if !l.ensureLength(q) {
			return &detector.Result{
				Status: detector.StatusDetected,
			}, nil
		}
	}

	return &detector.Result{
		Status: detector.StatusOk,
	}, nil
}

// ensureLength returns true if q domain/subdomain length is valid according to
// configured thresholds.  q must not be nil.
func (l *Length) ensureLength(q dns.Question) (ok bool) {
	if len(q.Name) > int(l.domainLen) {
		return false
	}

	for subdomain := range strings.SplitSeq(q.Name, ".") {
		if len(subdomain) > int(l.subdomainLen) {
			return false
		}
	}

	return true
}
