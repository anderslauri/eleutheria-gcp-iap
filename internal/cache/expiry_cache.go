package cache

import (
	"context"
	"time"
)

// ExpiryCache is an implementation of Cache interface with cache expiration built in.
type ExpiryCache struct {
	Cache[string, ExpiryCacheValue]
}

// ExpiryCacheValue is cache value for expiry cache. Exp represents unix timestamp in seconds.
type ExpiryCacheValue struct {
	Val string
	Exp int64
}

// NewExpiryCache creates a Cache interface implementation with cleaning (expiration) routine.
func NewExpiryCache(ctx context.Context, interval time.Duration) *ExpiryCache {
	c := &ExpiryCache{
		Cache: NewCopyOnWriteCache[string, ExpiryCacheValue](),
	}
	go c.cleaner(ctx, interval)
	return c
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
			e.Delete(func(_ string, val ExpiryCacheValue) bool {
				// Consider interval when looking at expiration timestamp.
				if (val.Exp + int64(interval.Seconds())) >= now {
					return true
				}
				return false
			})
		}
	}
}
