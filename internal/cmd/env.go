package cmd

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/caarlos0/env/v10"
)

type environment struct {
	// Redis caching configuration
	ClientIPsRedisKey     string        `env:"CLIENT_IP_REDIS_KEY"`
	ClientIPsRedisChannel string        `env:"CLIENT_IP_REDIS_CHANNEL"`
	ETLDRedisKey          string        `env:"ETLD_REDIS_KEY"`
	ETLDRedisChannel      string        `env:"ETLD_REDIS_CHANNEL"`
	RedisAddr             string        `env:"REDIS_ADDR"`
	RemoteSyncPeriod      time.Duration `env:"REMOTE_SYNC_PERIOD" envDefault:"5m"`
	RemoteEnabled         bool          `env:"REMOTE_ENABLED"`
	RemoteCleanupPeriod   time.Duration `env:"REMOTE_CLEANUP_PERIOD" envDefault:"5m"`

	CacheInvalidationPeriod time.Duration `env:"CACHE_INVALIDATION_PERIOD" envDefault:"24h"`

	// Log configuration
	Verbose uint8 `env:"verbose" envDefault:"0"`
}

// parseEnvironment parses environment.
func parseEnvironment() (e environment, err error) {
	err = env.Parse(&e)
	if err != nil {
		return environment{}, fmt.Errorf("reading environment: %w", err)
	}

	return e, nil
}

// logLevelFromVerbosity converts verbosity value to log level.
func logLevelFromVerbosity(verbosity uint8) (level slog.Level) {
	if verbosity > 0 {
		return slog.LevelDebug
	}

	return slog.LevelInfo
}
