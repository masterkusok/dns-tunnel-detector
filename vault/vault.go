// Package vault contains implementations for vault of blocked etld+1 domanis
// and clients.
//
// TOOD: finish vault concept.
package vault

import (
	"context"
	"net/netip"
)

// Interface is the interface for vault.
//
// TODO: Consider adding TTL for blocking?
type Interface interface {
	// AddClientIP adds ip to vault, and marks it blocked.
	AddClientIP(ctx context.Context, ip netip.Addr) (err error)

	// AddETLD adds top-level domain and marks is blocked.
	AddETLD(ctx context.Context, etld string) (err error)

	// CheckClientIP returns true if vault contains data about ip and it is
	// marked blocked.
	CheckClientIP(ctx context.Context, ip netip.Addr) (ok bool, err error)

	// CheckETLD returns true if vault contains data about ETLD and is marked
	// blocked.
	CheckETLD(ctx context.Context, etld string) (ok bool, err error)
}

// Empty is an empty vault that does nothing.
type Empty struct{}

// type check
var _ Interface = Empty{}

// AddClientIP implements the [Interface] for Empty.  err is always nil.
func (Empty) AddClientIP(_ context.Context, _ netip.Addr) (err error) {
	return nil
}

// AddETLD implements the [Interface] for Empty.  err is always nil
func (Empty) AddETLD(_ context.Context, _ string) (err error) {
	return nil
}

// CheckClientIP implements the [Interface] for Empty.  ok is always false.  err
// is always nil.
func (Empty) CheckClientIP(_ context.Context, _ netip.Addr) (ok bool, err error) {
	return false, nil
}

// CheckETLD implements the [Interface] for Empty.  ok is always false.  err is
// always nil.
func (Empty) CheckETLD(ctx context.Context, etld string) (ok bool, err error) {
	return false, nil
}
