package internal

import (
	"context"
	log "github.com/sirupsen/logrus"
	"io"
	"sync"
	"time"
)

type jwtCacheVal struct {
	// We don't need to store the entire token,
	// it is sufficient to store hash of token.
	val []byte
	exp int64
}

type jwtCache struct {
	cache sync.Map
}

// NewJwtCache creates a cache for JWT entries to be persisted.
func NewJwtCache(ctx context.Context) *jwtCache {
	cache := &jwtCache{}
	go cache.cleaner(ctx, 10*time.Minute)
	log.Info("JWT Cache successfully loaded.")
	return cache
}

// Set write content to jwt cache.
func (j *jwtCache) Set(param *CacheParams) {
	j.cache.Swap(param.key, &jwtCacheVal{
		val: param.val.([]byte),
		exp: param.ttl,
	})
}

// Get return item from jwt cache.
func (j *jwtCache) Get(key string) (any, bool) {
	entry, ok := j.cache.Load(key)
	if !ok {
		return nil, ok
	}
	return entry.(*jwtCacheVal).val, ok
}

// Read from cache into an io.Writer
func (j *jwtCache) Read(key string, w io.Writer) bool {
	val, ok := j.cache.Load(key)
	if !ok {
		return false
	}
	_, _ = w.Write(val.(*jwtCacheVal).val)
	return true
}

func (j *jwtCache) cleaner(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			keysToDelete := make(map[string]struct{})
			now := time.Now().Unix()

			j.cache.Range(func(key, value interface{}) bool {
				val, _ := value.(*jwtCacheVal)

				if (val.exp + int64(interval.Seconds())) >= now {
					keysToDelete[key.(string)] = struct{}{}
				}
				return true
			})
			for key, _ := range keysToDelete {
				j.cache.Delete(key)
			}
		}
	}
}
