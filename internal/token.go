package internal

import (
	"context"
	"errors"
	"fmt"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/anderslauri/k8s-gws-authn/internal/cache"
	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	googleIdToken           TokenType = "Id Token"
	googleSelfSignedToken   TokenType = "Self Signed"
	defaultLeeway                     = 30 * time.Second
	publicGoogleCerts                 = "https://www.googleapis.com/oauth2/v3/certs"
	selfSignedCertsPrefix             = "https://www.googleapis.com/service_accounts/v1/jwk/"
	publicGoogleCertsIssuer           = "https://accounts.google.com"
)

// GoogleTokenService is a backend representation to manage authn/authz of Google Tokens.
type GoogleTokenService struct {
	jwkClient http.Client
	once      sync.Once
	jwkSet    cache.Cache
	// keyFunc for issuer accounts.google.com - most commonly used.
	publicKeyFunc atomic.Value
}

// GoogleTokenClaims extends JWT with email claim.
type GoogleTokenClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
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

// Token interface for Token relevant functions, GoogleToken being implementation of Token.
type Token interface {
	Email() string
	Audience() string
	String() string
	Issuer() string
	Type() TokenType
}

// TokenType is a custom type definition for types of Google tokens which are supported.
type TokenType string

var (
	// ErrUnknownTokenType is given when no error is present, however, token type is not identifiable.
	ErrUnknownTokenType = errors.New("unknown token type")
	// ErrMissingEmailClaim is given when claim email is not present.
	ErrMissingEmailClaim = errors.New("missing email claim")
	// ErrMissingAudClaim is given when claim audience claim is not present.
	ErrMissingAudClaim = errors.New("missing aud claim")
	// ErrMissingJWK is given when no JWK can be found in cache or retrieved.
	ErrMissingJWK = errors.New("missing jwk")
)

// NewGoogleTokenService creates a new token service for Google Tokens.
func NewGoogleTokenService(ctx context.Context, jwkCache cache.Cache) (*GoogleTokenService, error) {
	googleTokenService := &GoogleTokenService{
		jwkSet: jwkCache,
	}
	// Load initial public certificates before starting.
	err := googleTokenService.googleCertsRefresher(ctx, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	return googleTokenService, nil
}

// readGoogleCerts is used when requesting JWK from Google Cloud.
func (t *GoogleTokenService) readGoogleCerts(ctx context.Context, url string, writer io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	rsp, err := t.jwkClient.Do(req)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()

	if _, err = io.Copy(writer, rsp.Body); err != nil {
		return err
	}
	return nil
}

// googleCertsRefresher starts a background routine to fetch JWK every 10 minutes,
// this is only for public certificates. For self-signed, this is done on demand.
func (t *GoogleTokenService) googleCertsRefresher(ctx context.Context, interval time.Duration) error {
	log.Info("Loading public certificates from Google.")
	buffer := getBuffer()
	defer putBuffer(buffer)

	if err := t.readGoogleCerts(ctx, publicGoogleCerts, buffer); err != nil {
		return err
	}
	keySet, err := keyfunc.NewJWKSetJSON(buffer.Bytes())
	if err != nil {
		return err
	}
	// Store key set in atomic.Value. Most common scenario.
	t.publicKeyFunc.Store(keySet)
	// Background routine for cache refresh of JWK for public certs.
	log.Info("Public certificates successfully loaded. Persisting in cache.")
	t.once.Do(func() {
		log.Infof("Background routine started, ensuring fresh certificates. Interval is %s.", interval.String())
		go func() {
			// Routine for keeping public certs synchronized.
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					buffer = getBuffer()
					if err := t.readGoogleCerts(ctx, publicGoogleCerts, buffer); err == nil {
						keySet, err := keyfunc.NewJWKSetJSON(buffer.Bytes())
						if err == nil {
							t.publicKeyFunc.Store(keySet)
						}
					}
					putBuffer(buffer)
				}
			}
		}()
	})
	return nil
}

// keyFunc retrieve JWK from Google API or local cache. Mostly cache.
func (t *GoogleTokenService) keyFunc(ctx context.Context, issuer string) (keyfunc.Keyfunc, error) {
	if issuer == publicGoogleCertsIssuer {
		return t.publicKeyFunc.Load().(keyfunc.Keyfunc), nil
	}
	buf := getBuffer()
	defer putBuffer(buf)

	var (
		keySet any
		err    error
		ok     bool
	)
	// Should only be for self-signed tokens.
	keySet, ok = t.jwkSet.Get(issuer)
	if !ok {
		if err = t.readGoogleCerts(ctx,
			fmt.Sprintf("%s%s", selfSignedCertsPrefix, issuer), buf); err != nil {
			return nil, ErrMissingJWK
		} else if keySet, err = keyfunc.NewJWKSetJSON(buf.Bytes()); err != nil {
			return nil, ErrMissingJWK
		}
		// Avoid making this non-blocking.
		go func(issuer string, val []byte) {
			params := cache.GetParams()
			defer cache.PutParams(params)
			params.Key = issuer
			params.Val = val
			t.jwkSet.Set(params)
		}(issuer, buf.Bytes())
		return keySet.(keyfunc.Keyfunc), nil
	}
	return keySet.(keyfunc.Keyfunc), nil
}

// NewGoogleToken transform base64 encoded token string into a GoogleToken representation, performs both claim
// assertion and verification that token is properly signed by Google or, by Google Service Account, JWK.
func (t *GoogleTokenService) NewGoogleToken(ctx context.Context, tokenString string, googleToken *GoogleToken) error {
	var issuer string
	// Identify issuer of token. This is a first pass - probably this should be optimized away.
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return err
	}
	issuer, _ = token.Claims.GetIssuer()

	tokenClaims := &GoogleTokenClaims{}
	defer putGoogleTokenClaims(tokenClaims)

	keySet, err := t.keyFunc(ctx, issuer)
	if err != nil {
		return err
	}
	if token, err := jwt.ParseWithClaims(tokenString, tokenClaims, keySet.Keyfunc,
		jwt.WithLeeway(defaultLeeway)); err != nil {
		return err
	} else if claims, ok := token.Claims.(*GoogleTokenClaims); ok && token.Valid {
		// Ensure claim email and aud is present. Also set defined
		// type of token given issuer value. If self-signed, issuer
		// will be equal to claim of email (service account).
		switch {
		case len(claims.Email) == 0:
			return ErrMissingEmailClaim
		case len(claims.Audience) == 0:
			return ErrMissingAudClaim
		case claims.Email == claims.Issuer:
			googleToken.typeOf = googleSelfSignedToken
		default:
			googleToken.typeOf = googleIdToken
		}
		googleToken.exp = claims.ExpiresAt.Time
		googleToken.iat = claims.IssuedAt.Time
		googleToken.issuer = claims.Issuer
		googleToken.aud = claims.Audience[0]
		googleToken.email = claims.Email
		return nil
	}
	return ErrUnknownTokenType
}