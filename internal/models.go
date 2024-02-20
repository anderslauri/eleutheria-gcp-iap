package internal

import (
	"context"
	"github.com/golang-jwt/jwt/v5"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Token interface for Token relevant functions, GoogleToken being the implementation of Token.
type Token interface {
	Email() string
	Audience() string
	String() string
	Issuer() string
	Type() TokenType
}

// Listener is an interface for the underlying listener implementation.
type Listener interface {
	Shutdown(ctx context.Context) error
	Port() int
}

// GoogleToken is an implementation of Token interface.
type GoogleToken struct {
	aud    string
	email  string
	issuer string
	iat    time.Time
	exp    time.Time
	typeOf TokenType
}

// GoogleTokenClaims normal JWT-claims extended with email claim.
type GoogleTokenClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

// GoogleTokenService is a backend representation to manage Google Token.
type GoogleTokenService struct {
	jwkClient http.Client
	once      sync.Once
	jwkSet    Cache
	// keyFunc for issuer accounts.google.com
	publicKeyFunc atomic.Value
}

// Cache is interface used to support whatever implementation is required.
type Cache interface {
	Set(param *CacheParams)
	Get(key string) (any, bool)
	Read(key string, writer io.Writer) bool
}

// CacheParams used when writing to underlying cache.
type CacheParams struct {
	val any
	key string
	ttl int64
}
