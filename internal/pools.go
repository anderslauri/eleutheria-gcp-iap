package internal

import (
	"bytes"
	"sync"
)

// Pooling for memory reuse.

var cacheParamPool = sync.Pool{
	New: func() interface{} {
		return &CacheParams{}
	},
}

var bufPool = sync.Pool{
	New: func() interface{} {
		buf := &bytes.Buffer{}
		buf.Grow(1024)
		return buf
	},
}

var googleTokenClaimsPool = sync.Pool{
	New: func() interface{} {
		return &GoogleTokenClaims{}
	},
}

var googleTokenPool = sync.Pool{
	New: func() interface{} {
		return &GoogleToken{}
	},
}

func getGoogleToken() *GoogleToken {
	return googleTokenPool.Get().(*GoogleToken)
}

func putGoogleToken(googleToken *GoogleToken) {
	googleToken.email = ""
	googleToken.aud = ""
	googleToken.issuer = ""
	googleTokenPool.Put(googleToken)
}

func getGoogleTokenClaims() *GoogleTokenClaims {
	return googleTokenClaimsPool.Get().(*GoogleTokenClaims)
}

func putGoogleTokenClaims(claims *GoogleTokenClaims) {
	claims.Email = ""
	claims.Issuer = ""
	claims.Audience = []string{""}
	claims.Subject = ""
	claims.ID = ""
	googleTokenClaimsPool.Put(claims)
}

func getBuffer() *bytes.Buffer {
	return bufPool.Get().(*bytes.Buffer)
}

func putBuffer(buf *bytes.Buffer) {
	buf.Reset()
	bufPool.Put(buf)
}

func getCacheParams() *CacheParams {
	return cacheParamPool.Get().(*CacheParams)
}

func putCacheParams(param *CacheParams) {
	param.ttl = 0
	param.key = ""
	param.val = nil
	cacheParamPool.Put(param)
}
