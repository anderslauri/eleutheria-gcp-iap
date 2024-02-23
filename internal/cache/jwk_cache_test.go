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
	cache := NewJwkCache(context.Background(), 100, 5*time.Minute)
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

	cache := &jwkCache{}
	cache.Set(&Params{
		Key: key,
		Val: []byte{},
	})
	go cache.cleaner(context.Background(), 1, 50*time.Millisecond, 0)
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
	cache := NewJwkCache(context.Background(), 100, 5*time.Minute)
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
