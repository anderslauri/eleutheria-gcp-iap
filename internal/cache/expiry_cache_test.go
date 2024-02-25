package cache

import (
	"context"
	"testing"
	"time"
)

func TestExpiryCacheCleanerRoutine(t *testing.T) {
	cache := NewExpiryCache(context.Background(), 50*time.Millisecond)

	key := "test"
	cache.Set(key,
		ExpiryCacheValue{
			Val: "",
			Exp: time.Now().Unix(),
		})
	for i := 0; i < 10; i++ {
		if _, ok := cache.Get(key); !ok {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("Expected entry to be purged from cache.")
}
