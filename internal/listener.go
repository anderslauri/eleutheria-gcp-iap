package internal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/anderslauri/k8s-gws-authn/internal/cache"
	log "github.com/sirupsen/logrus"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type listener struct {
	service               *http.Server
	port                  int
	xHeaderURI            string
	tokenService          *GoogleTokenService
	policyReader          PolicyReader
	googleWorkspaceClient GoogleWorkspaceReader
	jwtCache              cache.Cache
}

// Listener is an interface for the listener implementation.
type Listener interface {
	Shutdown(ctx context.Context) error
	Port() int
}

const (
	proxyAuthorizationHeader = "X-Forwarded-Proxy-Authorization"
	authorizationHeader      = "X-Forwarded-Authorization"
	defaultPolicyBindingRefresh = 5 * time.Minute
)

// NewListener creates a new HTTP-server. Non-blocking invocation, panic if not started correctly.
func NewListener(ctx context.Context, host, xURI string, port uint16) (Listener, error) {
	googleTokenService, err := NewGoogleTokenService(ctx, cache.NewJwkCache(ctx))
	if err != nil {
		return nil, err
	}

	googleWorkspaceReaderClient, err := NewGoogleWorkspaceReader(ctx)
	if err != nil {
		return nil, err
	}

	policyReaderService, err := NewProjectPolicyReaderService(ctx, googleWorkspaceReaderClient)
	if err != nil {
		return nil, err
	}
	// Precompile and cache all conditional expressions. No reason
	// to perform this for the first requests but rather do it here.
	for _, roles := range policyReaderService.UserRoleCollection() {
		for _, bindings := range roles {
			for _, binding := range bindings {
				if len(binding.Expression) == 0 {
					continue
				}
				// Force compiled program into cache, ignore output.
				_, _ = compileProgram(binding.Expression)
			}
		}
	}

	tcpListener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}

	l := &listener{
		service:               &http.Server{},
		xHeaderURI:            xURI,
		tokenService:          googleTokenService,
		port:                  tcpListener.Addr().(*net.TCPAddr).Port,
		policyReader:          policyReaderService,
		googleWorkspaceClient: googleWorkspaceReaderClient,
		jwtCache: cache.NewJwtCache(ctx),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", l.healthz)
	mux.HandleFunc("/auth", l.auth)
	l.service.Handler = mux
	// Listener.
	go func() {
		log.Info("Starting background listener for requests.")
		if err := l.service.Serve(tcpListener); err != http.ErrServerClosed {
			log.WithField("error", err).Fatal("Unable to start ListenAndServe.")
		}
	}()
	// Update all bindings in background to ensure a fresh cache is present.
	go func() {
		// TODO: Consume IAM-audit events to manage these policy changes in real time.
		ticker := time.NewTicker(defaultPolicyBindingRefresh)
		log.Infof("Starting background routine to refresh bindings every %s.", defaultPolicyBindingRefresh)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				log.Debugf("Updating bindings for role %s", iapRole)
				if err := policyReaderService.LoadUsersWithRoleForIdentityAwareProxy(ctx); err != nil {
					log.WithField("error", err).Errorf("Could not retrieve bindings for role %s.", iapRole)
					continue
				}
				log.Debugf("Bindings successfully updated for role %s", iapRole)
			}
		}
	}()
	return l, nil
}

// Port returns port of running listener.
func (l *listener) Port() int {
	return l.port
}

// Shutdown listener. Invocation is blocking.
func (l *listener) Shutdown(ctx context.Context) error {
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

	tokenHeaderValue := r.Header.Get(authorizationHeader)
	if xProxyAuthorization := r.Header.Get(proxyAuthorizationHeader); len(xProxyAuthorization) > 0 {
		tokenHeaderValue = xProxyAuthorization
	} else if len(tokenHeaderValue) == 0 {
		log.Debug("Request missing JWT.")
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	requestUrl, err := url.Parse(r.Header.Get(l.xHeaderURI))
	if err != nil {
		log.WithField("error", err).Error("Failed to parse request url.")
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	var (
		email UserID
		token *GoogleToken
	)
	// Bearer: is removed as prefix from header value.
	tokenString := strings.TrimSpace(tokenHeaderValue[7:])
	// Calculate hash for token. Identify if present in memory.
	requestUrlAudience := fmt.Sprintf("%s://%s", requestUrl.Scheme, requestUrl.Host)

	hasher := sha256.New()
	_, _ = hasher.Write([]byte(fmt.Sprintf("%s:%s",tokenString, requestUrlAudience)))
	tokenHash := hex.EncodeToString(hasher.Sum(nil))
	// Use token from cache if available.
	val, ok := l.jwtCache.Get(tokenHash)
	if ok {
		email = val.(UserID)
		goto verifyBindings
	}
	// Allocated new Google Token pointer. We have no value in cache.
	token = getGoogleToken()
	defer putGoogleToken(token)
	// Verify token and audience. We don't expect path to be present within audience.
	if err = l.tokenService.NewGoogleToken(ctx, tokenString, token); err != nil {
		log.WithField("error", err).Debug("Failed generating Google Token.")
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	} else if token.aud != requestUrlAudience {
		log.Debugf("Claim aud: %s does not match request url: %s.", token.aud, requestUrlAudience)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	email = UserID(token.email)
	// Write token to cache as token is valid for this audience value.
	go func() {
		params := cache.GetParams()
		defer cache.PutParams(params)
		// We only need to retain email from token, everything else is verified.
		params.Val = email
		params.Key = tokenHash
		params.TTL = token.exp.Unix()
		l.jwtCache.Set(params)
	}()

	verifyBindings:
	// Identify if user have binding for identity aware proxy. We identify directly referenced users and via GWS.
	bindings, err := l.policyReader.IdentityAwareProxyPolicyBindingForUser(email)
	if err != nil {
		log.WithField("error", err).Errorf("No policy binding found for user %s.", email)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	// params for evaluating expression in cel.
	params := map[string]any{
		"request.path": requestUrl.Path,
		"request.host": requestUrl.Host,
		"request.time": time.Now(),
	}
	if len(bindings) == 1 && len(bindings[0].Expression) > 0 {
		// Verify if conditional expression evaluates to true.
		if ok, err := doesConditionalExpressionEvaluateToTrue(bindings[0].Expression, params); !ok || err != nil {
			log.WithField("error", err).Warningf("Conditional expression is not valid for user %s.", email)
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		// Binding directly, also, via GWS. Weird times to be alive.
	} else if len(bindings) > 1 {
		isAuthorized := make(map[bool]struct{})
		log.Debugf("User %s has more than one active binding.", email)
		for _, binding := range bindings {
			if len(binding.Expression) == 0 {
				// Do nothing.
			} else if ok, err := doesConditionalExpressionEvaluateToTrue(binding.Expression, params); !ok || err != nil {
				isAuthorized[false] = struct{}{}
				continue
			}
			isAuthorized[true] = struct{}{}
		}
		if _, notAuthorized := isAuthorized[false]; notAuthorized {
			log.WithField("error", err).Warningf("Conditional expression is not valid for user %s.", email)
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
	}
	log.Debugf("Processing successful request with email: %s and audience: %s.", email, requestUrlAudience)
}