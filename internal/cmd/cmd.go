// Package cmd is the entrypoint for dns-tunnel-detector CLI.
package cmd

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/masterkusok/dns-tunnel-detector/detector"
	"github.com/masterkusok/dns-tunnel-detector/internal/handler"
	"github.com/masterkusok/dns-tunnel-detector/job/heuristic"
	"github.com/masterkusok/dns-tunnel-detector/job/statistic"
)

// TODO: extend.
var defaultJobs = []detector.Job{
	heuristic.NewEntropy(heuristic.DefaultThreshold),
	heuristic.NewLength(&heuristic.LengthConfig{
		AllowedDomainLength:    heuristic.DefaultAllowedDomainLength,
		AllowedSubdomainLength: heuristic.DefaultAllowedSubdomainLength,
	}),
	statistic.NewSubdomainCardinality(&statistic.SubdomainCardinalityConfig{
		Counter:        statistic.NewMapCounter(),
		MaxCardinality: statistic.DefaultMaxCardinality,
	}),
}

func Main() {
	ctx := context.Background()

	logger := slog.Default()
	logger.InfoContext(ctx, "running dns-tunnel-detector")

	config, err := parseConfig("config.yaml")
	checkError(ctx, logger, err)

	d := detector.New(&detector.Config{
		Jobs: defaultJobs,
	})

	h := handler.NewDefault(&handler.Config{
		Logger:   logger,
		Detector: d,
	})

	upstreams, err := upstreamsToInternal(config.UpstreamAddrs)
	checkError(ctx, logger, err)

	listenAddrs := config.ListenAddrs.toInternal()

	// TODO: support enrypyed protocols in config.
	p, err := proxy.New(&proxy.Config{
		Logger: logger,
		UpstreamConfig: &proxy.UpstreamConfig{
			Upstreams: upstreams,
		},
		UDPListenAddr:  listenAddrs.UDP,
		TCPListenAddr:  listenAddrs.TCP,
		RequestHandler: h,
	})
	checkError(ctx, logger, err)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	err = p.Start(ctx)
	checkError(ctx, logger, err)

	<-signalChan

	p.Shutdown(ctx)
}

// checkError logs error and exits the application if err is not nil.  l must
// not be nil.
func checkError(ctx context.Context, l *slog.Logger, err error) {
	if err != nil {
		l.ErrorContext(ctx, "fatal error", "error", err)

		os.Exit(1)
	}
}
