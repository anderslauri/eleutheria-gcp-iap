package cache

import "sync"

var paramPool = sync.Pool{
	New: func() interface{} {
		return &Params{}
	},
}

// GetParams returns params for cache from memory pool.
func GetParams() *Params {
	return paramPool.Get().(*Params)
}

// PutParams return Param struct to memory pool.
func PutParams(param *Params) {
	param.TTL = 0
	param.Key = ""
	param.Val = nil
	paramPool.Put(param)
}
