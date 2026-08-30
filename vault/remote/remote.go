// Package remote contains implementations of remote vault source.
package remote

import (
	"context"
)

// Interface represents the remote set of string identifiers.
//
// TODO: Upd docs, they seem meaningless to me.
type Interface interface {
	// NotifyAdd notifies remote that new value was added to cache.
	NotifyAdd(ctx context.Context, v string)

	// Notifications returns notification chanel.
	Notifications() (res <-chan string)

	// Map returns all the items in remote.  It is used for full synchronization
	// with remote cache.
	Map(ctx context.Context) (res map[string]struct{})
}

// Empty is the [Interface] implementation that does nothing.
type Empty struct{}

// NotifyAdd implements the [Interface] for Empty.
func (Empty) NotifyAdd(_ context.Context, _ string) {}

// Notifications implements the [Interface] for Empty.  It always returns new
// channel.
func (Empty) Notifications() (res <-chan string) {
	return make(<-chan string)
}

// Map implements the [Interface] for Empty.  It always returns nil.
func (Empty) Map(ctx context.Context) (res map[string]struct{}) {
	return nil
}
