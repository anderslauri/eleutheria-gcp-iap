package cache

import (
	"context"
	"time"
)

// ExpiryCache is an implementation of Cache interface with cache expiration built in.
type ExpiryCache struct {
	Cache
}

// ExpiryCacheValue is cache value for expiry cache. Exp represents unix timestamp in seconds.
type ExpiryCacheValue struct {
	Val any
	Exp int64
}

// NewExpiryCache creates a Cache interface implementation with cleaning (expiration) routine.
func NewExpiryCache(ctx context.Context, interval time.Duration) *ExpiryCache {
	c := &ExpiryCache{
		NewCopyOnWriteCache(),
	}
	go c.cleaner(ctx, interval)
	return c
}

// Set append to cache with expiration.
func (e *ExpiryCache) Set(key string, val ExpiryCacheValue) {
	e.Cache.Set(key, val)
}

// Get value with expiration information.
func (e *ExpiryCache) Get(key string) (ExpiryCacheValue, bool) {
	val, ok := e.Cache.Get(key)
	if !ok {
		return ExpiryCacheValue{}, false
	}
	return val.(ExpiryCacheValue), true
}

func (e *ExpiryCache) cleaner(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().Unix()
			e.Delete(func(_ string, val any) bool {
				entry, _ := val.(ExpiryCacheValue)
				// Consider interval when looking at expiration timestamp.
				if (entry.Exp + int64(interval.Seconds())) >= now {
					return true
				}
				return false
			})
		}
	}
}
