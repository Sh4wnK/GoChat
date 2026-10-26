package broker

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis is a Broker backed by Redis pub/sub. Room broadcasts are
// published on channel "room:<name>", direct messages on
// "user:<id>", and typos/user events on "*".
type Redis struct {
	node   string
	client *redis.Client
	log    *slog.Logger
}

// NewRedis connects to Redis at addr.
func NewRedis(addr string, log *slog.Logger) *Redis {
	return &Redis{
		node:   nodeID(),
		client: redis.NewClient(&redis.Options{Addr: addr}),
		log:    log,
	}
}

// NewRedisWithClient wraps an existing client (used in tests with
// miniredis).
func NewRedisWithClient(node string, client *redis.Client, log *slog.Logger) *Redis {
	return &Redis{node: node, client: client, log: log}
}

func (r *Redis) Publish(ctx context.Context, msg Message) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return r.client.Publish(ctx, channelFor(msg.Channel), payload).Err()
}

func (r *Redis) Subscribe(ctx context.Context) <-chan Sub {
	out := make(chan Sub, 1024)
	pubsub := r.client.PSubscribe(ctx, "gochat:*")
	go func() {
		defer close(out)
		ch := pubsub.Channel()
		for {
			select {
			case <-ctx.Done():
				_ = pubsub.Close()
				return
			case m, ok := <-ch:
				if !ok {
					return
				}
				var msg Message
				if err := json.Unmarshal([]byte(m.Payload), &msg); err != nil {
					out <- Sub{Err: err}
					continue
				}
				if msg.Origin == r.node {
					continue // never echo own messages
				}
				select {
				case out <- Sub{Message: msg}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}

func (r *Redis) NodeID() string { return r.node }

// Ping verifies the Redis connection; used for fast startup failure.
func (r *Redis) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

func (r *Redis) Close() error {
	if r.client == nil {
		return nil
	}
	return r.client.Close()
}

func channelFor(channel string) string {
	return "gochat:" + channel
}

func nodeID() string {
	return "node-" + time.Now().UTC().Format("20060102T150405.000000000")
}

// ErrRedisUnavailable is returned by the server when the broker cannot
// reach Redis at startup in multi-node mode.
var ErrRedisUnavailable = errors.New("redis unavailable")
