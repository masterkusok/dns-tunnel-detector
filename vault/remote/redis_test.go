package remote_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/masterkusok/dns-tunnel-detector/internal/testutil"
	"github.com/masterkusok/dns-tunnel-detector/vault/remote"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const envDefaultRedisPort = "TEST_REDIS_PORT"

const (
	testTimeout = 1 * time.Second

	testDB  = 15
	testKey = "set"
)

// redisTestPort is a helper, that returns test redis port from the environment
// and skips test if the port is not set.
func redisTestPort(tb testing.TB) (port uint64) {
	portStr := os.Getenv(envDefaultRedisPort)
	if portStr == "" {
		tb.Skipf("test redis port is not set, skipping;")
	}

	port, err := strconv.ParseUint(portStr, 10, 32)
	require.NoError(tb, err)

	return port
}

// newTestRedis returns properly initialized remote.Redis for tests and
// registers DB flush in cleanup.  Also it returns underlying redis client.
func newTestRedis(tb testing.TB, channel string) (r *remote.Redis, client *redis.Client) {
	tb.Helper()

	port := redisTestPort(tb)
	client = redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("127.0.0.1:%d", port),
		DB:   testDB,
	})

	r = remote.NewRedis(tb.Context(), &remote.RedisConfig{
		Logger:             testutil.NewDiscardLogger(),
		Client:             client,
		Key:                testKey,
		Channel:            channel,
		CleanupTicker:      time.NewTicker(time.Hour),
		InvalidationPeriod: time.Hour,
	})

	tb.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		_, err := client.FlushAll(ctx).Result()
		require.NoError(tb, err)
		require.NoError(tb, r.Close())
	})

	return r, client
}

// subscriptionItem represents single item from Redis pub sub channel.
type subscriptionItem struct {
	ClientID string `json:"client_id"`
	Payload  string `json:"payload"`
}

func TestRedis_NotifyAdd(t *testing.T) {
	pubSubChan := uuid.New().String()
	r, client := newTestRedis(t, pubSubChan)

	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	t.Cleanup(cancel)

	pubSub := client.Subscribe(ctx, pubSubChan)

	ch := pubSub.Channel()

	want := "192.0.2.0"
	r.NotifyAdd(ctx, want)

	msg, ok := <-ch
	require.True(t, ok)

	var gotItem subscriptionItem
	err := json.Unmarshal([]byte(msg.Payload), &gotItem)
	require.NoError(t, err)

	var got netip.Addr
	err = got.UnmarshalText([]byte(gotItem.Payload))
	require.NoError(t, err)

	assert.Equal(t, want, got.String())

	members, err := client.ZRange(ctx, testKey, 0, -1).Result()
	require.NoError(t, err)
	assert.Contains(t, members, want)
}

func TestRedis_Notifications(t *testing.T) {
	pubSubChan := uuid.New().String()
	r, client := newTestRedis(t, pubSubChan)

	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	t.Cleanup(cancel)

	ch := r.Notifications()

	want := "192.0.2.0"
	encodedItem, err := json.Marshal(subscriptionItem{
		ClientID: "foo",
		Payload:  want,
	})
	require.NoError(t, err)

	receiversNum, err := client.Publish(ctx, pubSubChan, encodedItem).Result()
	require.Equal(t, int64(1), receiversNum)
	require.NoError(t, err)

	gotItem, ok := <-ch
	require.True(t, ok)

	assert.Equal(t, want, gotItem)
}

func TestRedis_Map(t *testing.T) {
	pubSubChan := uuid.New().String()
	r, client := newTestRedis(t, pubSubChan)

	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	t.Cleanup(cancel)

	want := map[string]struct{}{
		"192.0.2.0": {},
		"192.0.2.1": {},
	}

	expiresAt := time.Now().Add(time.Hour).UnixNano()
	for k := range want {
		_, err := client.ZAdd(ctx, testKey, redis.Z{
			Score:  float64(expiresAt),
			Member: k,
		}).Result()
		require.NoError(t, err)
	}

	got := r.Map(ctx)
	assert.True(t, cmp.Equal(want, got))
}

func TestRedis_Map_expired(t *testing.T) {
	pubSubChan := uuid.New().String()
	r, client := newTestRedis(t, pubSubChan)

	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	t.Cleanup(cancel)

	want := map[string]struct{}{
		"192.0.2.0": {},
		"192.0.2.1": {},
	}

	expiresAt := time.Now().Add(-1 * time.Hour).UnixNano()
	for k := range want {
		_, err := client.ZAdd(ctx, testKey, redis.Z{
			Score:  float64(expiresAt),
			Member: k,
		}).Result()
		require.NoError(t, err)
	}

	got := r.Map(ctx)
	assert.Empty(t, got)
}
