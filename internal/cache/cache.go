package cache

import (
	"maps"
	"sync"
	"sync/atomic"
)

// Cache is a very generic cache interface to support an array of underlying implementations.
type Cache[K comparable, V any] interface {
	Set(key K, val V)
	Get(key K) (V, bool)
	Delete(del func(key K, val V) bool)
}

// Map is a custom map type definition.
type Map[K comparable, V any] map[K]V

// CopyOnWriteCache is an implementation of Cache interface.
type CopyOnWriteCache[K comparable, V any] struct {
	cache        atomic.Pointer[Map[K, V]]
	wLock, dLock sync.Mutex
}

// NewCopyOnWriteCache returns a cache implementation interface of Cache interface.
func NewCopyOnWriteCache[K comparable, V any]() *CopyOnWriteCache[K, V] {
	copyOnWriteCache := &CopyOnWriteCache[K, V]{}
	copyOnWriteCache.cache.Store(&Map[K, V]{})
	return copyOnWriteCache
}

// Delete items from cache.
func (c *CopyOnWriteCache[K, V]) Delete(del func(key K, val V) bool) {
	c.dLock.Lock()
	orgMap := *c.cache.Load()

	keysToDelete := make([]K, 0, 100)
	for k, v := range orgMap {
		if ok := del(k, v); ok {
			keysToDelete = append(keysToDelete, k)
		}
	}
	c.dLock.Unlock()
	if len(keysToDelete) == 0 {
		return
	}
	c.wLock.Lock()
	defer c.wLock.Unlock()
	newMap := make(Map[K, V], len(orgMap)-len(keysToDelete))
	for _, key := range keysToDelete {
		delete(newMap, key)
	}
	c.cache.Store(&newMap)
}

// Set item to cache.
func (c *CopyOnWriteCache[K, V]) Set(key K, val V) {
	c.wLock.Lock()
	defer c.wLock.Unlock()
	orgMap := c.cache.Load()
	newMap := maps.Clone(*orgMap)
	newMap[key] = val
	c.cache.Store(&newMap)
}

// Get value from cache.
func (c *CopyOnWriteCache[K, V]) Get(key K) (V, bool) {
	orgMap := *c.cache.Load()
	val, ok := orgMap[key]
	return val, ok
}
