package store

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type GoRedisClient struct {
	client *redis.Client
}

type GoRedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
}

func NewGoRedisClient(cfg *GoRedisConfig) (*GoRedisClient, error) {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping failed: %w", err)
	}
	return &GoRedisClient{client: client}, nil
}

func (c *GoRedisClient) Close() error { return c.client.Close() }

func (c *GoRedisClient) Set(ctx context.Context, key string, value any, exp time.Duration) error {
	return c.client.Set(ctx, key, value, exp).Err()
}
func (c *GoRedisClient) Get(ctx context.Context, key string) (string, error) {
	return c.client.Get(ctx, key).Result()
}
func (c *GoRedisClient) Del(ctx context.Context, keys ...string) error {
	return c.client.Del(ctx, keys...).Err()
}
func (c *GoRedisClient) SAdd(ctx context.Context, key string, members ...any) error {
	return c.client.SAdd(ctx, key, members...).Err()
}
func (c *GoRedisClient) SMembers(ctx context.Context, key string) ([]string, error) {
	return c.client.SMembers(ctx, key).Result()
}
func (c *GoRedisClient) HSet(ctx context.Context, key string, values ...any) error {
	return c.client.HSet(ctx, key, values...).Err()
}
func (c *GoRedisClient) HGet(ctx context.Context, key, field string) (string, error) {
	return c.client.HGet(ctx, key, field).Result()
}
func (c *GoRedisClient) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	return c.client.HGetAll(ctx, key).Result()
}
func (c *GoRedisClient) HDel(ctx context.Context, key string, fields ...string) error {
	return c.client.HDel(ctx, key, fields...).Err()
}
func (c *GoRedisClient) Expire(ctx context.Context, key string, exp time.Duration) error {
	return c.client.Expire(ctx, key, exp).Err()
}
func (c *GoRedisClient) TTL(ctx context.Context, key string) (time.Duration, error) {
	return c.client.TTL(ctx, key).Result()
}
func (c *GoRedisClient) Exists(ctx context.Context, keys ...string) (int64, error) {
	return c.client.Exists(ctx, keys...).Result()
}
func (c *GoRedisClient) Eval(ctx context.Context, script string, keys []string, args ...any) (any, error) {
	return c.client.Eval(ctx, script, keys, args...).Result()
}
