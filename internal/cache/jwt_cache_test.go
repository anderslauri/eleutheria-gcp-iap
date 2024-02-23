package cache

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestJwtCacheWriteAndRead(t *testing.T) {
	var (
		key = "test"
		val = []byte{'a', 'b', 'c'}
	)
	cache := NewJwtCache(context.Background(), 5*time.Minute)
	cache.Set(&Params{
		Key: key,
		Val: val,
	})
	if cacheVal, ok := cache.Get(key); !ok || !bytes.Equal(val, cacheVal.([]byte)) {
		t.Fatal("Expected value to be found in cache.")
	}
}

func TestJwtCacheCleanerRoutine(t *testing.T) {
	var key = "test"

	cache := &jwtCache{}
	go cache.cleaner(context.Background(), 1*time.Second)

	cache.Set(&Params{
		Key: key,
		TTL: time.Now().Unix(),
		Val: []byte{},
	})
	for i := 0; i < 10; i++ {
		if _, ok := cache.Get(key); !ok {
			return
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatal("Expected entry to be purged from cache.")
}

func TestJwtWriteAndReadFromCache(t *testing.T) {
	var (
		key = "test"
		val = []byte{'a', 'b', 'c'}
	)
	cache := NewJwtCache(context.Background(), 5*time.Minute)
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
