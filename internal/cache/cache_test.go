package cache_test

import (
	"github.com/anderslauri/open-iap/internal/cache"
	"testing"
)

var (
	defaultCacheKey = "test"
)

func TestNewCopyOnWriteCache(t *testing.T) {
	copyWriteCache := cache.NewCopyOnWriteCache[string, cache.ExpiryCacheValue[string]]()
	copyWriteCache.Set(defaultCacheKey,
		cache.ExpiryCacheValue[string]{
			Val: "",
			Exp: 0,
		})
	if _, ok := copyWriteCache.Get(defaultCacheKey); !ok {
		t.Fatal("No cache result found in cache.")
	}
}

func BenchmarkCopyOnWriteCacheReading(b *testing.B) {
	copyOnWriteCache := cache.NewCopyOnWriteCache[string, string]()

	copyOnWriteCache.Set(defaultCacheKey, defaultCacheKey)
	for i := 0; i < b.N; i++ {
		_, _ = copyOnWriteCache.Get(defaultCacheKey)
	}
}
