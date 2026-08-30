package vault

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/masterkusok/dns-tunnel-detector/internal/syncutil"
	"github.com/masterkusok/dns-tunnel-detector/vault/remote"
)

// Config is the configuration structure for *Default.
type Config struct {
	// Logger is used for logging vault operations.  It must not be nil.
	Logger *slog.Logger

	// ETLDRemote is the remote source for blocked ETLD cache.  It must not be
	// nil.
	ETLDRemote remote.Interface

	// ClientIPRemote is the remote source for blocked client IP addresses
	// cache.  It must not be nil.
	ClientIPRemote remote.Interface

	// FallbackTicker is used for planning full synchronizations with remote.
	FallbackTicker *time.Ticker

	// RemoteEnabled defines whether cache must be synchronized with remote.
	RemoteEnabled bool
}

// Default is the default implementation of the [Interface].
type Default struct {
	logger         *slog.Logger
	clientIPData   *syncutil.Map[string, struct{}]
	etldData       *syncutil.Map[string, struct{}]
	clientIPRemote remote.Interface
	etldRemote     remote.Interface
}

// New returns properly initialized *Default.  conf must not be nil and must be
// valid.
func New(ctx context.Context, conf *Config) (d *Default) {
	d = &Default{
		logger:         conf.Logger,
		clientIPData:   syncutil.NewMap[string, struct{}](0),
		etldData:       syncutil.NewMap[string, struct{}](0),
		clientIPRemote: conf.ClientIPRemote,
		etldRemote:     conf.ETLDRemote,
	}

	if !conf.RemoteEnabled {
		return d
	}

	// Initial synchronization.
	d.syncWithRemote(ctx)

	go func() {
		for range conf.FallbackTicker.C {
			d.syncWithRemote(ctx)
		}
	}()

	go d.handleNotifications(d.clientIPRemote.Notifications(), d.clientIPData)
	go d.handleNotifications(d.etldRemote.Notifications(), d.etldData)

	return d
}

// handleNotifications handles data update notifications from remote.  c and
// data must not be nil.  It is intended to be run concurrently.
func (d *Default) handleNotifications(c <-chan string, data *syncutil.Map[string, struct{}]) {
	for v := range c {
		data.Set(v, struct{}{})
	}
}

// type check
var _ Interface = (*Default)(nil)

// AddClientIP implements the [Interface] for *Default.
func (d *Default) AddClientIP(ctx context.Context, addr netip.Addr) (err error) {
	addrStr := addr.String()
	d.clientIPData.Set(addrStr, struct{}{})
	d.clientIPRemote.NotifyAdd(ctx, addrStr)

	return nil
}

// AddETLD implements the [Interface] for *Default.
func (d *Default) AddETLD(ctx context.Context, etld string) (err error) {
	d.etldData.Set(etld, struct{}{})
	d.etldRemote.NotifyAdd(ctx, etld)

	return nil
}

// CheckClientIP implements the [Interface] for *Default.
func (d *Default) CheckClientIP(_ context.Context, addr netip.Addr) (ok bool, err error) {
	_, ok = d.clientIPData.Get(addr.String())

	return ok, nil
}

// CheckETLD implements the [Interface] for *Default.
func (d *Default) CheckETLD(_ context.Context, etld string) (ok bool, err error) {
	_, ok = d.etldData.Get(etld)

	return ok, nil
}

// syncWithRemote synchronizes local vault variables with remote origin.
func (d *Default) syncWithRemote(ctx context.Context) {
	func() {
		d.logger.DebugContext(ctx, "client ip remote vault sync started", "len", d.clientIPData.Len())
		defer d.logger.DebugContext(ctx, "client ip remote vault sync finished", "len", d.clientIPData.Len())

		newData := d.clientIPRemote.Map(ctx)
		if newData == nil {
			d.logger.DebugContext(ctx, "got empty client ip data from remote")

			return
		} else {
			d.clientIPData.Load(newData)
		}
	}()

	func() {
		d.logger.DebugContext(ctx, "etld remote vault sync started", "len", d.etldData.Len())
		defer d.logger.DebugContext(ctx, "etld remote vault sync finished", "len", d.etldData.Len())

		newData := d.etldRemote.Map(ctx)
		if newData == nil {
			d.logger.DebugContext(ctx, "got empty etld data from remote")

			return
		} else {
			d.etldData.Load(newData)
		}
	}()
}
