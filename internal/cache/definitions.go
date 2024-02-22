package cache

import (
	"io"
)

// Cache is interface used to support whatever implementation is required.
type Cache interface {
	Set(param *Params)
	Get(key string) (any, bool)
	Read(key string, writer io.Writer) bool
}

// Params used when writing to underlying cache.
type Params struct {
	Val any
	Key string
	TTL int64
}
