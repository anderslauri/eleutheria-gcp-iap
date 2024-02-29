package internal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/anderslauri/open-iap/internal/cache"
	"github.com/golang-jwt/jwt/v5/request"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/iamcredentials/v1"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type listener struct {
	service               *http.Server
	tcpListener           net.Listener
	port                  int
	xOriginalHeader       string
	token                 TokenVerifier[*GoogleTokenClaims]
	policyClient          PolicyBindingClientReader
	googleWorkspaceClient GoogleWorkspaceClientReader
	tokenCache            cache.Cache[string, cache.ExpiryCacheValue[UserID]]
}

// Listener is an interface for a listener implementation.
type Listener interface {
	Close(ctx context.Context) error
	Port() int
	Open(ctx context.Context) error
}

// NewListener creates a new HTTP-server. Listen(ctx...) must be invoked from calling routine to start listening.
func NewListener(ctx context.Context, host, xHeaderUri string, port uint16,
	refreshPublicCertsInterval, jwkCacheCleanInterval, jwtCacheCleanInterval,
	policyBindingRefreshInterval, leeway time.Duration) (Listener, error) {

	credentials, err := google.FindDefaultCredentials(ctx,
		admin.AdminDirectoryGroupReadonlyScope,
		iamcredentials.CloudPlatformScope,
	)
	if err != nil {
		return nil, err
	}
	log.Info("Loading new reader client for Google Workspace.")
	googleWorkspaceClient, err := NewGoogleWorkspaceClient(ctx, credentials)
	if err != nil {
		return nil, err
	}
	log.Info("Loading new client for project policy bindings and conditional expressions identification.")
	policyBindingClient, err := NewPolicyBindingClient(ctx,
		googleWorkspaceClient, credentials, policyBindingRefreshInterval)
	if err != nil {
		return nil, err
	}
	log.Info("Starting client for Google Tokens.")

	googleTokenService, err := NewGoogleTokenService(ctx,
		cache.NewExpiryCache[keyfunc.Keyfunc](ctx, refreshPublicCertsInterval), jwkCacheCleanInterval, leeway)
	if err != nil {
		return nil, err
	}
	tcpListener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}
	l := &listener{
		service:               &http.Server{},
		tcpListener:           tcpListener,
		xOriginalHeader:       xHeaderUri,
		token:                 googleTokenService,
		port:                  tcpListener.Addr().(*net.TCPAddr).Port,
		policyClient:          policyBindingClient,
		googleWorkspaceClient: googleWorkspaceClient,
		tokenCache:            cache.NewExpiryCache[UserID](ctx, jwtCacheCleanInterval),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", l.healthz)
	mux.HandleFunc("GET /auth", l.auth)
	l.service.Handler = mux
	log.Info("Listener is successfully configured.")
	return l, nil
}

// Port returns port of running listener.
func (l *listener) Port() int {
	return l.port
}

// Open listener to incoming requests. Blocking.
func (l *listener) Open(_ context.Context) error {
	return l.service.Serve(l.tcpListener)
}

// Close listener. Blocking.
func (l *listener) Close(ctx context.Context) error {
	return l.service.Shutdown(ctx)
}

func (l *listener) healthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (l *listener) auth(w http.ResponseWriter, r *http.Request) {
	tokenString, _ := request.HeaderExtractor{"Proxy-Authorization", "Authorization"}.ExtractToken(r)
	requestURL, err := url.Parse(r.Header.Get(l.xOriginalHeader))
	// Ensure both request url and tokenString are valid.
	if err != nil || len(requestURL.String()) == 0 ||
		(len(tokenString) < 7 || !strings.EqualFold(tokenString[:7], "bearer:")) {
		log.WithField("error", err).Error("Failed to parse request url or token header value.")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// Re-slice string that we remove Bearer: prefix - also remove an optional blank space if present.
	tokenString = strings.TrimPrefix(tokenString[7:], " ")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		aud       = fmt.Sprintf("%s://%s", requestURL.Scheme, requestURL.Host)
		now       = time.Now().Unix()
		tokenHash = fmt.Sprintf("%s:%s", tokenString, aud)
		email     UserID
		claims    *GoogleTokenClaims
	)
	hasher := sha256.New()
	// Verify if Google Service Account JWT is present within local cache, if found and exp is valid,
	// jump to role binding processing as token requires no re-processing given the fully valid status.
	if _, err = hasher.Write([]byte(tokenHash)); err != nil {
		log.WithField("error", err).Warning("hasher.Write: returned error. Unexpected.")
	} else if entry, ok := l.tokenCache.Get(hex.EncodeToString(hasher.Sum(nil))); ok && entry.Exp < now {
		email = entry.Val
		goto verifyGoogleCloudPolicyBindings
	}

	claims = getGoogleTokenClaims()
	defer putGoogleTokenClaims(claims)
	// Verify token validity, signature and audience.
	if err = l.token.Verify(ctx, tokenString, aud, claims); err != nil {
		log.WithField("error", err).Error("Failed generating or verifying token.")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	email = UserID(claims.Email)
	// Append to cache.
	go l.tokenCache.Set(tokenHash,
		cache.ExpiryCacheValue[UserID]{
			Val: email,
			Exp: claims.ExpiresAt.Unix(),
		})
	// Identify if user has role bindings in project.
verifyGoogleCloudPolicyBindings:
	bindings, err := l.policyClient.IdentityAwareProxyPolicyBindingForUser(email)
	if err != nil {
		log.WithField("error", err).Warningf("No policy role binding found for user %s.", email)
		w.WriteHeader(http.StatusUnauthorized)
		return
	} else if len(bindings) == 1 && len(bindings[0].Expression) == 0 {
		// We have a single role binding without a conditional expression. User is authenticated.
		return
	}
	// Identity Aware Proxy supported parameters for evaluating conditional expression given bindings.
	params := map[string]any{
		"request.path": requestURL.Path,
		"request.host": requestURL.Host,
		"request.time": now,
	}
	if len(bindings) == 1 && len(bindings[0].Expression) > 0 {
		log.Debugf("User %s has single conditional policy expression. Evaluating.", email)
		isAuthorized, err := doesConditionalExpressionEvaluateToTrue(bindings[0].Expression, params)
		if !isAuthorized || err != nil {
			log.WithField("error", err).Errorf("Conditional expression with title %s is not valid for user %s.",
				bindings[0].Title, email)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		return
	}
	log.Debugf("User %s has multiple conditional policy expressions. Evaluating", email)

	for _, binding := range bindings {
		if len(binding.Expression) == 0 {
			continue
		} else if ok, err := doesConditionalExpressionEvaluateToTrue(binding.Expression, params); !ok || err != nil {
			log.WithField("error", err).Errorf("Conditional expression with title %s is not valid for user %s.",
				binding.Title, email)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	log.Debugf("Processing successful request with email: %s and audience: %s.", email, aud)
}
