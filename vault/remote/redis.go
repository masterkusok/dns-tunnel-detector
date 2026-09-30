package remote

import (
	"context"
	_ "embed"
	"encoding/json"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// RedisConfig is the configuration structure for [Redis].
type RedisConfig struct {
	// Logger is used for logging vault operations.  It must not be nil.
	Logger *slog.Logger

	// Client is used for querying Redis.  It must not be nil.
	Client *redis.Client

	// InvalidationPeriod is the period for which cache records will be stored
	// in Redis.
	InvalidationPeriod time.Duration

	// CleanupTicker is used for cleaning up stale records in a Redis remote.
	// It must not be nil.
	CleanupTicker *time.Ticker

	// Key is the key of target set in Redis.
	Key string

	// Channel is the name of channel with notifications.
	Channel string
}

// Redis is the implementation of the [Interface] that uses Redis as remote.
type Redis struct {
	logger          *slog.Logger
	client          *redis.Client
	pubSub          *redis.PubSub
	cleanupTicker   *time.Ticker
	pubSubWg        sync.WaitGroup
	notifications   chan string
	clientID        string
	key             string
	channel         string
	invalidationIvl time.Duration
}

// NewRedis returns properly initialized *Redis.  conf must not be nil and must
// be valid.
func NewRedis(ctx context.Context, conf *RedisConfig) (r *Redis) {
	r = &Redis{
		clientID: uuid.New().String(),
		logger:   conf.Logger,
		client:   conf.Client,
		pubSub:   conf.Client.Subscribe(ctx, conf.Channel),
		pubSubWg: sync.WaitGroup{},
		// TODO: Make this value configurable, this one is cringe.
		notifications:   make(chan string, 100),
		key:             conf.Key,
		channel:         conf.Channel,
		invalidationIvl: conf.InvalidationPeriod,
		cleanupTicker:   conf.CleanupTicker,
	}

	r.pubSubWg.Go(func() {
		r.handleSub(ctx)
	})

	go func() {
		r.cleanup(ctx)
	}()

	return r
}

// cleanup removes stale records from remote ZSet.  It is intended to be run in
// a separate goroutine.
func (r *Redis) cleanup(ctx context.Context) {
	for range r.cleanupTicker.C {
		r.logger.DebugContext(ctx, "remote cleanup started")

		now := time.Now().UnixNano()
		_, err := r.client.ZRemRangeByScore(ctx, r.key, "-inf", strconv.FormatInt(now, 10)).Result()
		if err != nil {
			r.logger.ErrorContext(ctx, "cleaning up stale records", "error", err)
		}
	}
}

// handleSub handles new items from subcription.  It is intended to be run in a
// separate goroutine.
func (r *Redis) handleSub(ctx context.Context) {
	for msg := range r.pubSub.Channel() {
		var item subscriptionItem
		err := json.Unmarshal([]byte(msg.Payload), &item)
		if err != nil {
			r.logger.ErrorContext(ctx, "parsing subcription item", "error", err)

			continue
		}

		// NOTE: Ignore our ID to prevent pub recursion.
		if item.ClientID == r.clientID {
			continue
		}

		r.notifications <- item.Payload
	}
}

// subscriptionItem represents single notification for Redis pub sub channel.
type subscriptionItem struct {
	ClientID string `json:"client_id"`
	Payload  string `json:"payload"`
}

// NotifyAdd implements the [Interface] for the *Redis.
func (r *Redis) NotifyAdd(ctx context.Context, v string) {
	expiresAt := time.Now().Add(r.invalidationIvl).UnixNano()
	added, err := r.client.ZAdd(ctx, r.key, redis.Z{
		Score:  float64(expiresAt),
		Member: v,
	}).Result()
	if err != nil {
		r.logger.ErrorContext(ctx, "setting item in redis", "error", err)

		return
	}

	if added == 1 {
		r.pubNotify(ctx, v)
	}
}

// pubNotify writes notification into a configured Redis pub sub channel.
func (r *Redis) pubNotify(ctx context.Context, payload string) {
	item := subscriptionItem{
		ClientID: r.clientID,
		Payload:  payload,
	}

	encodedItem, err := json.Marshal(item)
	if err != nil {
		r.logger.ErrorContext(ctx, "encoding notification message", "error", err)

		return
	}

	receiversCount, err := r.client.Publish(ctx, r.channel, encodedItem).Result()
	if err != nil {
		r.logger.ErrorContext(ctx, "sending notification message", "error", err)

		return
	}

	r.logger.InfoContext(ctx, "sent notification message", "receivers_count", receiversCount)
}

// Notifications implements the [Interface] for the *Redis.
func (r *Redis) Notifications() (res <-chan string) {
	return r.notifications
}

// Map implements the [Interface] for the *Redis.
func (r *Redis) Map(ctx context.Context) (res map[string]struct{}) {
	r.logger.DebugContext(ctx, "fetching remote vault members")

	expiry := time.Now().UnixNano()
	// TODO: Optimize using SSCAN op.
	members, err := r.client.ZRangeArgs(ctx, redis.ZRangeArgs{
		Key:     r.key,
		Start:   strconv.FormatInt(expiry+1, 10),
		Stop:    "inf",
		ByScore: true,
	}).Result()
	if err != nil {
		r.logger.ErrorContext(ctx, "fetching remote set", "error", err)

		return nil
	}

	res = make(map[string]struct{}, len(members))
	for _, member := range members {
		res[member] = struct{}{}
	}

	return res
}

// type check
var _ io.Closer = (*Redis)(nil)

// Close implements the [io.Closer] interface for *Redis.
func (r *Redis) Close() (err error) {
	err = r.pubSub.Close()
	if err != nil {
		return err
	}

	r.pubSubWg.Wait()

	close(r.notifications)
	r.cleanupTicker.Stop()

	return nil
}
