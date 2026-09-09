// Package cmd is the entrypoint for dns-tunnel-detector CLI.
package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/masterkusok/dns-tunnel-detector/detector"
	"github.com/masterkusok/dns-tunnel-detector/internal/handler"
	"github.com/masterkusok/dns-tunnel-detector/job/heuristic"
	"github.com/masterkusok/dns-tunnel-detector/job/statistic"
	"github.com/masterkusok/dns-tunnel-detector/vault"
	"github.com/masterkusok/dns-tunnel-detector/vault/remote"
	"github.com/redis/go-redis/v9"
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

	envs, err := parseEnvironment()
	checkError(ctx, slog.Default(), err)

	logger := slog.New(slog.NewTextHandler(
		os.Stdout,
		&slog.HandlerOptions{
			Level: logLevelFromVerbosity(envs.Verbose),
		}),
	)
	logger.InfoContext(ctx, "running dns-tunnel-detector")

	config, err := parseConfig("config.yaml")
	checkError(ctx, logger, err)

	var (
		clientIPRemote remote.Interface
		etldRemote     remote.Interface
	)

	if envs.RemoteEnabled {
		client := redis.NewClient(&redis.Options{
			Addr: envs.RedisAddr,
		})

		_, err = client.Ping(ctx).Result()
		checkError(ctx, logger, fmt.Errorf("sending ping to redis remote: %w", err))

		cRedis := remote.NewRedis(ctx, &remote.RedisConfig{
			Logger:  logger.With("prefix", "client_ip_remote"),
			Client:  client,
			Key:     envs.ClientIPsRedisKey,
			Channel: envs.ClientIPsRedisChannel,
		})
		defer cRedis.Close()

		eRedis := remote.NewRedis(ctx, &remote.RedisConfig{
			Logger:  logger.With("prefix", "etld_remote"),
			Client:  client,
			Key:     envs.ETLDRedisKey,
			Channel: envs.ETLDRedisChannel,
		})
		defer eRedis.Close()

		clientIPRemote = cRedis
		etldRemote = eRedis
	} else {
		clientIPRemote = remote.Empty{}
		etldRemote = remote.Empty{}
	}

	vault := vault.New(ctx, &vault.Config{
		Logger:         logger.With("prefix", "vault"),
		ETLDRemote:     etldRemote,
		ClientIPRemote: clientIPRemote,
		FallbackTicker: time.NewTicker(envs.RemoteSyncPeriod),
		RemoteEnabled:  envs.RemoteEnabled,
	})

	d := detector.New(&detector.Config{
		Logger: logger,
		Jobs:   defaultJobs,
		Vault:  vault,
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
