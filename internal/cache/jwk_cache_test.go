package cache

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestJwkCacheWriteAndRead(t *testing.T) {
	var (
		key = "test"
		val = []byte{'a', 'b', 'c'}
	)
	cache := NewJwkCache(context.Background())
	cache.Set(&Params{
		Key: key,
		Val: val,
	})
	if cacheVal, ok := cache.Get(key); !ok || !bytes.Equal(val, cacheVal.([]byte)) {
		t.Fatal("Expected value to be found in cache.")
	}
}

func TestJwkCacheCleanerRoutine(t *testing.T) {
	var key = "test"

	cache := &jwkCache{
		minLen: 0,
		ttl:    0,
	}
	cache.Set(&Params{
		Key: key,
		Val: []byte{},
	})
	go cache.cleaner(context.Background(), 50*time.Millisecond)
	for i := 0; i < 10; i++ {
		if _, ok := cache.Get(key); !ok {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("Expected entry to be purged from cache.")
}

func TestJwkWriteAndReadFromCache(t *testing.T) {
	var (
		key = "test"
		val = []byte{'a', 'b', 'c'}
	)
	cache := NewJwkCache(context.Background())
	cache.Set(&Params{
		Key: key,
		Val: val,
	})
	buf := &bytes.Buffer{}

	if ok := cache.Read(key, buf); !ok {
		t.Fatal("Expected value to be found in cache.")
	} else if !bytes.Equal(buf.Bytes(), val) {
		t.Fatal("Expected value found in cache to be identical.")
	}
}
