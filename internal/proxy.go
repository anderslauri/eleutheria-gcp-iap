package internal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/anderslauri/open-iap/internal/cache"
	"github.com/golang-jwt/jwt/v5/request"
	log "github.com/sirupsen/logrus"
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
	xHeaderURI            string
	tokenService          *GoogleTokenService
	policyReader          PolicyReader
	googleWorkspaceClient GoogleWorkspaceReader
	jwtCache              cache.Cache
}

// Listener is an interface for a listener implementation.
type Listener interface {
	Close(ctx context.Context) error
	Port() int
	Open(ctx context.Context) error
}

const (
	proxyAuthorizationHeader = "X-Forwarded-Proxy-Authorization"
	authorizationHeader      = "X-Forwarded-Authorization"
)

// NewListener creates a new HTTP-server. Listen(ctx...) must be invoked from calling routine to start listening.
func NewListener(ctx context.Context, host, xHeaderUri string, port uint16,
	refreshPublicCertsInterval, jwkCacheCleanInterval, jwtCacheCleanInterval,
	policyBindingRefreshInterval time.Duration) (Listener, error) {

	log.Info("Starting client for Google Tokens.")
	googleTokenService, err := NewGoogleTokenService(ctx,
		cache.NewJwkCache(ctx, 100, jwkCacheCleanInterval), refreshPublicCertsInterval)
	if err != nil {
		return nil, err
	}
	log.Info("Starting client for Google Workspace.")
	googleWorkspaceReaderClient, err := NewGoogleWorkspaceReader(ctx)
	if err != nil {
		return nil, err
	}
	log.Info("Starting client for Project policy bindings and conditional expressions.")
	policyReaderService, err := NewProjectPolicyReaderService(ctx,
		googleWorkspaceReaderClient, policyBindingRefreshInterval)
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
		xHeaderURI:            xHeaderUri,
		tokenService:          googleTokenService,
		port:                  tcpListener.Addr().(*net.TCPAddr).Port,
		policyReader:          policyReaderService,
		googleWorkspaceClient: googleWorkspaceReaderClient,
		jwtCache:              cache.NewJwtCache(ctx, jwtCacheCleanInterval),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", l.healthz)
	mux.HandleFunc("/auth", l.auth)
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
	if r.Method != "GET" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (l *listener) auth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Extract bearer token.
	tokenString, _ := request.HeaderExtractor{proxyAuthorizationHeader, authorizationHeader}.ExtractToken(r)
	// Extract request url.
	requestURL, err := url.Parse(r.Header.Get(l.xHeaderURI))
	if err != nil || (len(tokenString) < 7 || !strings.EqualFold(tokenString[:7], "bearer:")) {
		log.WithField("error", err).Debug("Failed to parse request url or token header value.")
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	// Re-slice string that we remove Bearer: prefix - also remove an optional blank space if present.
	tokenString = strings.TrimPrefix(tokenString[7:], " ")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		audience  = fmt.Sprintf("%s://%s", requestURL.Scheme, requestURL.Host)
		hasher    = sha256.New()
		tokenHash string
		email     UserID
		token     *GoogleToken
	)
	if _, err = hasher.Write([]byte(fmt.Sprintf("%s:%s", tokenString, audience))); err != nil {
		log.WithField("error", err).Warning("hasher.Write: returned error. Unexpected.")
	} else {
		// Load token from cache.
		if val, ok := l.jwtCache.Get(hex.EncodeToString(hasher.Sum(nil))); ok {
			email = val.(UserID)
			goto verifyGoogleCloudPolicyBindings
		}
	}
	token = getGoogleToken()
	defer putGoogleToken(token)
	// Verify token validity, signature and audience.
	if err = l.tokenService.NewGoogleToken(ctx, tokenString, token); err != nil || token.aud != audience {
		log.WithField("error", err).Debug("Failed generating or verifying token.")
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	email = UserID(token.email)
	// Append token to cache.
	go func() {
		params := cache.GetParams()
		defer cache.PutParams(params)
		// We only need to retain email from token - everything else is verified.
		params.Val = email
		params.Key = tokenHash
		params.TTL = token.exp.Unix()
		l.jwtCache.Set(params)
	}()
	// Identify if user has role bindings in project.
verifyGoogleCloudPolicyBindings:
	bindings, err := l.policyReader.IdentityAwareProxyPolicyBindingForUser(email)
	if err != nil {
		log.WithField("error", err).Warningf("No policy role binding found for user %s.", email)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	} else if len(bindings) == 1 && len(bindings[0].Expression) == 0 {
		// We have a single role binding without a conditional expression. User is authenticated.
		return
	}
	// Identity Aware Proxy supported parameters for evaluating conditional expression given bindings.
	params := map[string]any{
		"request.path": requestURL.Path,
		"request.host": requestURL.Host,
		"request.time": time.Now(),
	}
	if len(bindings) == 1 && len(bindings[0].Expression) > 0 {
		log.Debugf("User %s has single conditional policy expression. Evaluating.", email)
		isAuthorized, err := doesConditionalExpressionEvaluateToTrue(bindings[0].Expression, params)
		if !isAuthorized || err != nil {
			log.WithField("error", err).Warningf("Conditional expression with title %s is not valid for user %s.",
				bindings[0].Title, email)
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		return
	}
	log.Debugf("User %s has multiple conditional policy expressions. Evaluating", email)

	for _, binding := range bindings {
		if len(binding.Expression) == 0 {
			continue
		} else if ok, err := doesConditionalExpressionEvaluateToTrue(binding.Expression, params); !ok || err != nil {
			log.WithField("error", err).Warningf("Conditional expression with title %s is not valid for user %s.",
				binding.Title, email)
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
	}
	log.Debugf("Processing successful request with email: %s and audience: %s.", email, audience)
}
