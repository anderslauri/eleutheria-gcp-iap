package internal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/anderslauri/open-iap/internal/cache"
	log "github.com/sirupsen/logrus"
	"net/url"
	"time"
)

// Authenticator is generic interface for authentication.
type Authenticator interface {
	Authenticate(ctx context.Context, credentials string, requestUrl url.URL) error
}

// GoogleCloudTokenAuthenticator is an implementation of Authenticator interface.
type GoogleCloudTokenAuthenticator struct {
	token     TokenVerifier[*GoogleTokenClaims]
	iamClient IdentityAccessManagementReader
	gwsClient GoogleWorkspaceClientReader
	cache     cache.Cache[string, cache.ExpiryCacheValue[UserID]]
}

// ErrInvalidGoogleCloudAuthentication is given as a general error when Authenticate(...) is not successful.
var ErrInvalidGoogleCloudAuthentication = errors.New("invalid google cloud authentication")

// NewGoogleCloudTokenAuthenticator returns an implementation of interface Authenticator
func NewGoogleCloudTokenAuthenticator(v TokenVerifier[*GoogleTokenClaims], c cache.Cache[string, cache.ExpiryCacheValue[UserID]], i IdentityAccessManagementReader, g GoogleWorkspaceClientReader) (*GoogleCloudTokenAuthenticator, error) {
	return &GoogleCloudTokenAuthenticator{
		token:     v,
		iamClient: i,
		gwsClient: g,
		cache:     c,
	}, nil
}

// Authenticate verifies if Google credentials are valid.
func (g *GoogleCloudTokenAuthenticator) Authenticate(ctx context.Context, credentials string, requestUrl url.URL) error {
	var (
		aud       = fmt.Sprintf("%s://%s", requestUrl.Scheme, requestUrl.Host)
		now       = time.Now().Unix()
		tokenHash = fmt.Sprintf("%s:%s", credentials, aud)
		email     UserID
		claims    *GoogleTokenClaims
	)
	hasher := sha256.New()
	// Verify if Google Service Account JWT is present within local cache, if found and exp is valid,
	// jump to role binding processing as token requires no re-processing given the fully valid status.
	if _, err := hasher.Write([]byte(tokenHash)); err != nil {
		log.WithField("error", err).Warning("hasher.Write: returned error. Unexpected.")
	} else if entry, ok := g.cache.Get(hex.EncodeToString(hasher.Sum(nil))); ok && entry.Exp < now {
		email = entry.Val
		goto verifyGoogleCloudPolicyBindings
	}
	claims = getGoogleTokenClaims()
	defer putGoogleTokenClaims(claims)
	// Verify token validity, signature and audience.
	if err := g.token.Verify(ctx, credentials, aud, claims); err != nil {
		log.WithField("error", err).Error("Failed verifying token.")
		return err
	}
	email = UserID(claims.Email)
	// Append to cache.
	go g.cache.Set(tokenHash,
		cache.ExpiryCacheValue[UserID]{
			Val: email,
			Exp: claims.ExpiresAt.Unix(),
		})
	// Identify if user has role bindings in project.
verifyGoogleCloudPolicyBindings:
	bindings, err := g.iamClient.IdentityAwareProxyPolicyBindingForUser(email)
	if err != nil {
		log.WithField("error", err).Warningf("No policy role binding found for user %s.", email)
		return err
	} else if len(bindings) == 1 && len(bindings[0].Expression) == 0 {
		// We have a single role binding without a conditional expression. User is authenticated.
		return nil
	}
	// Identity Aware Proxy supported parameters for evaluating conditional expression given bindings.
	params := map[string]any{
		"request.path": requestUrl.Path,
		"request.host": requestUrl.Host,
		"request.time": now,
	}
	if len(bindings) == 1 && len(bindings[0].Expression) > 0 {
		log.Debugf("User %s has single conditional policy expression. Evaluating.", email)
		isAuthorized, err := doesConditionalExpressionEvaluateToTrue(bindings[0].Expression, params)
		if !isAuthorized || err != nil {
			log.WithField("error", err).Errorf("Conditional expression with title %s is not valid for user %s.",
				bindings[0].Title, email)
			return ErrInvalidGoogleCloudAuthentication
		}
		return nil
	}
	log.Debugf("User %s has multiple conditional policy expressions. Evaluating", email)

	for _, binding := range bindings {
		if len(binding.Expression) == 0 {
			continue
		} else if ok, err := doesConditionalExpressionEvaluateToTrue(binding.Expression, params); !ok || err != nil {
			log.WithField("error", err).Errorf("Conditional expression %s is not valid for user %s.",
				binding.Title, email)
			return ErrInvalidGoogleCloudAuthentication
		}
	}
	log.Debugf("Processing successful request with email: %s and audience: %s.", email, requestUrl.String())
	return nil
}
