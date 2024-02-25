package cache

import (
	"context"
	"time"
)

// ExpiryCache is an implementation of Cache interface with cache expiration built in.
type ExpiryCache[V any] struct {
	Cache[string, ExpiryCacheValue[V]]
}

// ExpiryCacheValue is cache value for expiry cache. Exp represents unix timestamp in seconds.
type ExpiryCacheValue[V any] struct {
	Val V
	Exp int64
}

// NewExpiryCache creates a Cache interface implementation with cleaning (expiration) routine.
func NewExpiryCache[V any](ctx context.Context, interval time.Duration) *ExpiryCache[V] {
	c := &ExpiryCache[V]{
		Cache: NewCopyOnWriteCache[string, ExpiryCacheValue[V]](),
	}
	go c.cleaner(ctx, interval)
	return c
}

func (e *ExpiryCache[V]) cleaner(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().Unix()
			e.Delete(func(_ string, val ExpiryCacheValue[V]) bool {
				// Consider interval when looking at expiration timestamp.
				if (val.Exp + int64(interval.Seconds())) >= now {
					return true
				}
				return false
			})
		}
	}
}
