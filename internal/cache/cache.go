package cache

import (
	"maps"
	"sync"
	"sync/atomic"
)

// Cache is interface used to support whatever implementation is required.
type Cache interface {
	Set(key string, val any)
	Get(key string) (any, bool)
	Delete(del func(key string, val any) bool)
}

// CopyOnWriteCache is an implementation of Cache interface.
type CopyOnWriteCache struct {
	cache        atomic.Value
	wLock, dLock sync.Mutex
}

// NewCopyOnWriteCache returns a cache implementation interface of Cache interface.
func NewCopyOnWriteCache() *CopyOnWriteCache {
	copyOnWriteCache := &CopyOnWriteCache{}
	copyOnWriteCache.cache.Store(make(map[string]any, 100))
	return copyOnWriteCache
}

// Delete items from cache.
func (c *CopyOnWriteCache) Delete(del func(key string, val any) bool) {
	c.dLock.Lock()
	orgMap, _ := c.cache.Load().(map[string]any)
	keysToDelete := make([]string, 0, 100)
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
	newMap := maps.Clone(orgMap)
	for _, key := range keysToDelete {
		delete(newMap, key)
	}
	c.cache.Store(newMap)
}

// Set item to cache.
func (c *CopyOnWriteCache) Set(key string, val any) {
	c.wLock.Lock()
	defer c.wLock.Unlock()
	orgMap, _ := c.cache.Load().(map[string]any)
	newMap := maps.Clone(orgMap)
	newMap[key] = val
	c.cache.Store(newMap)
}

// Get value from cache.
func (c *CopyOnWriteCache) Get(key string) (any, bool) {
	orgMap, _ := c.cache.Load().(map[string]any)
	if val, ok := orgMap[key]; ok {
		return val, true
	}
	return nil, false
}
