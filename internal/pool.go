package internal

import (
	"bytes"
	"sync"
)

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
