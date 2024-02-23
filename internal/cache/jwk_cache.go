package cache

import (
	"context"
	log "github.com/sirupsen/logrus"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

type jwkCache struct {
	cache atomic.Value
	mutex sync.Mutex
	// ttl in seconds.
	ttl int64
}

type jwkCacheType map[string]jwkCacheVal

type jwkCacheVal struct {
	jwk any
	// write timestamp.
	wts int64
}

// NewJwkCache creates a new cache for JWK. Mostly read, thus we apply copy on write.
func NewJwkCache(ctx context.Context, minEntries uint, cleanCacheInterval time.Duration) *jwkCache {
	cache := &jwkCache{}
	// Google service account JWK are valid at least 24h - makes little sense to use smaller cache here.
	go cache.cleaner(ctx, minEntries, cleanCacheInterval, 86400)
	log.Info("JWK Cache successfully loaded.")
	return cache
}

// Get retrieve value from JWK cache.
func (j *jwkCache) Get(key string) (any, bool) {
	cache, _ := j.cache.Load().(jwkCacheType)
	val, ok := cache[key]
	return val.jwk, ok
}

// Read from cache into an io.Writer
func (j *jwkCache) Read(key string, w io.Writer) bool {
	cache, _ := j.cache.Load().(jwkCacheType)
	val, ok := cache[key]
	if !ok {
		return false
	} else if _, ok := val.jwk.([]byte); ok {
		_, _ = w.Write(val.jwk.([]byte))
		return true
	}
	return false
}

// cleaner - removes self-signed JWK after 24h. This is when they expire (or rotate),
// see: https://cloud.google.com/iam/docs/service-account-creds#google-managed-keys
func (j *jwkCache) cleaner(ctx context.Context, minCacheEntries uint, interval time.Duration, ttl int64) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			currentCache, _ := j.cache.Load().(jwkCacheType)

			if len(currentCache) < int(minCacheEntries) {
				continue
			}
			keysToDelete := make(map[string]struct{})

			now := time.Now().Add(interval).Unix()
			for key, val := range currentCache {
				if (now - val.wts) >= ttl {
					keysToDelete[key] = struct{}{}
				}
			}
			if len(keysToDelete) > 0 {
				j.delete(keysToDelete)
			}
		}
	}
}

// delete removes key from JWK cache.
func (j *jwkCache) delete(keys map[string]struct{}) {
	j.mutex.Lock()
	defer j.mutex.Unlock()
	orgCache, _ := j.cache.Load().(jwkCacheType)
	newCache := make(jwkCacheType, len(orgCache)-len(keys))
	// Ignore any removed keys. Copy and write.
	for key, val := range orgCache {
		if _, ok := keys[key]; !ok {
			newCache[key] = val
		}
	}
	j.cache.Store(newCache)
}

// Set writes new entry in JWK-cache.
func (j *jwkCache) Set(param *Params) {
	j.mutex.Lock()
	defer j.mutex.Unlock()
	orgCache, _ := j.cache.Load().(jwkCacheType)
	// Create a new map with same length, copy all
	// content and replace map within atomic.Value.
	newCache := make(jwkCacheType, len(orgCache)+1)
	// Copy and write.
	for k, v := range orgCache {
		newCache[k] = v
	}
	newCache[param.Key] = jwkCacheVal{
		jwk: param.Val,
		wts: time.Now().Unix(),
	}
	j.cache.Store(newCache)
}
