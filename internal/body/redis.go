package body

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var ErrUnknownDriver = errors.New("unknown body store driver")

type RedisStore struct {
	client  *redis.Client
	timeout time.Duration
}

func NewRedisStore(url string, timeout time.Duration) (*RedisStore, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}

	opt.ReadTimeout = timeout
	opt.WriteTimeout = timeout
	opt.DialTimeout = timeout

	return &RedisStore{client: redis.NewClient(opt), timeout: timeout}, nil
}

func (s *RedisStore) Get(ctx context.Context, driver, store, key string) ([]byte, error) {
	if driver != "redis" {
		return nil, ErrUnknownDriver
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	return s.client.Get(ctx, key).Bytes()
}

func (s *RedisStore) GetMany(ctx context.Context, driver, store string,
	keys []string) ([][]byte, error) {

	if driver != "redis" {
		return nil, ErrUnknownDriver
	}

	if len(keys) == 0 {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	vals, err := s.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}

	if len(vals) != len(keys) {
		return nil, fmt.Errorf("mget returned %d values for %d keys",
			len(vals), len(keys))
	}

	out := make([][]byte, len(keys))

	for i, v := range vals {
		switch raw := v.(type) {
		case string:
			out[i] = []byte(raw)
		case []byte:
			out[i] = raw
		}
	}

	return out, nil
}

func (s *RedisStore) Put(ctx context.Context, key string, value []byte,
	ttl time.Duration) error {

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	return s.client.Set(ctx, key, value, ttl).Err()
}

func (s *RedisStore) Close() error { return s.client.Close() }

func (s *RedisStore) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	return s.client.Ping(ctx).Err()
}
