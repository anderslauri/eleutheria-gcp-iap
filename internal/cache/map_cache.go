package cache

import (
	"io"
	"sync"
	"sync/atomic"
)

type mapCopyOnWriteCache struct {
	cache atomic.Value
	mutex sync.Mutex
}

type mapCopyOnWriteCacheType map[string]any

// NewCopyOnWriteCache returns a cache implementation interface of Cache. This cache is growth only.
func NewCopyOnWriteCache() *mapCopyOnWriteCache {
	return &mapCopyOnWriteCache{}
}

// Set item to cache.
func (c *mapCopyOnWriteCache) Set(param *Params) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	orgMap, _ := c.cache.Load().(mapCopyOnWriteCacheType)
	newMap := make(mapCopyOnWriteCacheType, len(orgMap)+1)

	for k, v := range orgMap {
		newMap[k] = v
	}
	newMap[param.Key] = param.Val
	c.cache.Store(newMap)
}

// Get item from cache.
func (c *mapCopyOnWriteCache) Get(key string) (any, bool) {
	orgMap, _ := c.cache.Load().(mapCopyOnWriteCacheType)

	val, ok := orgMap[key]
	if !ok {
		return nil, ok
	}
	return val, ok
}

// Read value from cache into writer. Not implemented.
func (c *mapCopyOnWriteCache) Read(_ string, _ io.Writer) bool {
	return false
}
