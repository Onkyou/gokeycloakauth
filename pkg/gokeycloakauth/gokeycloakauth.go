package gokeycloakauth

//	courtesy to original for gin-keycloak to https://github.com/tbaehler/gin-keycloak

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
	"golang.org/x/oauth2"
	"gopkg.in/go-jose/go-jose.v2/jwt"
)

type contextKey string

// VarianceTimer controls the max runtime of Auth() and AuthChain() middleware
var VarianceTimer = 30000 * time.Millisecond
var publicKeyCache = cache.New(8*time.Hour, 8*time.Hour)

// TokenContainer stores all relevant token information
type TokenContainer struct {
	Token         *oauth2.Token
	KeyCloakToken *KeyCloakToken
}

func extractToken(r *http.Request) (*oauth2.Token, error) {
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		return nil, errors.New("no authorization header")
	}

	th := strings.Split(hdr, " ")
	if len(th) != 2 {
		return nil, errors.New("incomplete authorization header")
	}

	return &oauth2.Token{AccessToken: th[1], TokenType: th[0]}, nil
}

func GetTokenContainer(token *oauth2.Token, config KeycloakConfig) (*TokenContainer, error) {

	keyCloakToken, err := decodeToken(token, config)
	if err != nil {
		return nil, err
	}

	return &TokenContainer{
		Token: &oauth2.Token{
			AccessToken: token.AccessToken,
			TokenType:   token.TokenType,
		},
		KeyCloakToken: keyCloakToken,
	}, nil
}

func getPublicKey(keyId string, config KeycloakConfig) (interface{}, error) {

	keyEntry, err := getPublicKeyFromCacheOrBackend(keyId, config)
	if err != nil {
		return nil, err
	}
	if strings.ToUpper(keyEntry.Kty) == "RSA" {
		n, _ := base64.RawURLEncoding.DecodeString(keyEntry.N)
		bigN := new(big.Int)
		bigN.SetBytes(n)
		e, _ := base64.RawURLEncoding.DecodeString(keyEntry.E)
		bigE := new(big.Int)
		bigE.SetBytes(e)
		return &rsa.PublicKey{N: bigN, E: int(bigE.Int64())}, nil
	} else if strings.ToUpper(keyEntry.Kty) == "EC" {
		x, _ := base64.RawURLEncoding.DecodeString(keyEntry.X)
		bigX := new(big.Int)
		bigX.SetBytes(x)
		y, _ := base64.RawURLEncoding.DecodeString(keyEntry.Y)
		bigY := new(big.Int)
		bigY.SetBytes(y)

		var curve elliptic.Curve
		crv := strings.ToUpper(keyEntry.Crv)
		switch crv {
		case "P-224":
			curve = elliptic.P224()
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, errors.New("EC curve algorithm not supported " + keyEntry.Kty)
		}

		return &ecdsa.PublicKey{
			Curve: curve,
			X:     bigX,
			Y:     bigY,
		}, nil
	}

	return nil, errors.New("no support for keys of type " + keyEntry.Kty)
}

func getPublicKeyFromCacheOrBackend(keyId string, config KeycloakConfig) (KeyEntry, error) {
	entry, exists := publicKeyCache.Get(keyId)
	if exists {
		return entry.(KeyEntry), nil
	}

	u, err := url.Parse(config.Url)
	if err != nil {
		return KeyEntry{}, err
	}

	if config.FullCertsPath != nil {
		u.Path = *config.FullCertsPath
	} else {
		u.Path = path.Join(u.Path, "realms", config.Realm, "protocol/openid-connect/certs")
	}

	httpClient := http.DefaultClient
	if config.HTTPClient != nil {
		httpClient = config.HTTPClient
	}
	resp, err := httpClient.Get(u.String())
	if err != nil {
		return KeyEntry{}, err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	var certs Certs
	err = json.Unmarshal(body, &certs)
	if err != nil {
		return KeyEntry{}, err
	}

	for _, keyIdFromServer := range certs.Keys {
		if keyIdFromServer.Kid == keyId {
			publicKeyCache.Set(keyId, keyIdFromServer, cache.DefaultExpiration)
			return keyIdFromServer, nil
		}
	}

	return KeyEntry{}, errors.New("no public key found with kid " + keyId + " found")
}

func decodeToken(token *oauth2.Token, config KeycloakConfig) (*KeyCloakToken, error) {
	keyCloakToken := KeyCloakToken{}

	var err error
	parsedJWT, err := jwt.ParseSigned(token.AccessToken)
	if err != nil {
		slog.Error("gokeycloakauth jwt not decodable", "err", err)
		return nil, err
	}
	key, err := getPublicKey(parsedJWT.Headers[0].KeyID, config)
	if err != nil {
		slog.Error("failed to get publickey", "err", err)
		return nil, err
	}

	err = parsedJWT.Claims(key, &keyCloakToken)
	if err != nil {
		slog.Error("failed to get claims JWT", "err", err)
		return nil, err
	}

	if config.CustomClaimsMapper != nil {
		err = config.CustomClaimsMapper(parsedJWT, &keyCloakToken)
		if err != nil {
			slog.Error("failed to get custom claims JWT", "err", err)
			return nil, err
		}
	}

	return &keyCloakToken, nil
}

func isExpired(token *KeyCloakToken) bool {
	if token.Exp == 0 {
		return false
	}
	now := time.Now()
	fromUnixTimestamp := time.Unix(token.Exp, 0)
	return now.After(fromUnixTimestamp)
}

func getTokenContainer(r *http.Request, config KeycloakConfig) (*TokenContainer, bool) {
	oauthToken, err := extractToken(r)
	if err != nil {
		slog.Error("gokeycloakauth Cannot extract oauth2.Token", "err", err)
		return nil, false
	}
	if !oauthToken.Valid() {
		slog.Info("gokeycloakauth Invalid Token - nil or expired")
		return nil, false
	}

	tc, err := GetTokenContainer(oauthToken, config)
	if err != nil {
		slog.Error("gokeycloakauth Cannot extract TokenContainer", "err", err)
		return nil, false
	}
	if isExpired(tc.KeyCloakToken) {
		slog.Error("gokeycloakauth Keycloak Token has expired")
		return nil, false
	}
	return tc, true
}

func (t *TokenContainer) Valid() bool {
	if t.Token == nil {
		return false
	}
	return t.Token.Valid()
}

type ClaimMapperFunc func(jsonWebToken *jwt.JSONWebToken, keyCloakToken *KeyCloakToken) error

type KeycloakConfig struct {
	Url                string
	Realm              string
	FullCertsPath      *string
	CustomClaimsMapper ClaimMapperFunc
	HTTPClient         *http.Client
}

func AuthFunc(fn func(http.ResponseWriter, *http.Request, string), config KeycloakConfig, accessCheckFunctions ...AccessCheckFunction) func(http.Handler) http.HandlerFunc {
	return func(next http.Handler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			done := make(chan bool, 1)

			go func() {
				tc, ok := getTokenContainer(r, config)
				if !ok || !tc.Valid() {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					done <- false
					return
				}

				// Run access check functions
				for _, fnCheck := range accessCheckFunctions {
					if fnCheck(tc, r) {
						// Store token in context
						ctx := context.WithValue(r.Context(), "keycloak_token", tc.KeyCloakToken)
						r = r.WithContext(ctx)

						// Call the provided callback with the access token string
						fn(w, r, tc.Token.AccessToken)

						done <- true
						return
					}
				}

				http.Error(w, "forbidden", http.StatusForbidden)
				done <- false
			}()

			select {
			case ok := <-done:
				if !ok {
					slog.Info("gokeycloakauth access denied", "duration", time.Since(start), "url", r.URL.Path)
					return
				}
				slog.Info("gokeycloakauth access granted", "duration", time.Since(start), "url", r.URL.Path)
				next.ServeHTTP(w, r) // call next handler after fn callback
			case <-time.After(VarianceTimer):
				http.Error(w, "authorization timeout", http.StatusGatewayTimeout)
				slog.Info("gokeycloakauth timeout", "duration", time.Since(start), "url", r.URL.Path)
			}
		}
	}
}

func Auth(config KeycloakConfig, accessCheckFunctions ...AccessCheckFunction) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			done := make(chan bool, 1)

			go func() {
				tc, ok := getTokenContainer(r, config)
				if !ok || !tc.Valid() {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					done <- false
					return
				}

				// Run access check functions
				for _, fn := range accessCheckFunctions {
					if fn(tc, r) {
						// Store token in context
						ctx := context.WithValue(r.Context(), "keycloak_token", tc.KeyCloakToken)
						r = r.WithContext(ctx)

						done <- true
						return
					}
				}

				http.Error(w, "forbidden", http.StatusForbidden)
				done <- false
			}()

			select {
			case ok := <-done:
				if !ok {
					slog.Info("gokeycloakauth access denied", "duration", time.Since(start), "url", r.URL.Path)
					return
				}
				slog.Info("gokeycloakauth access granted", "duration", time.Since(start), "url", r.URL.Path)
				next.ServeHTTP(w, r)
			case <-time.After(VarianceTimer):
				http.Error(w, "authorization timeout", http.StatusGatewayTimeout)
				slog.Info("gokeycloakauth timeout", "duration", time.Since(start), "url", r.URL.Path)
			}
		})
	}
}

// RequestLogger returns a net/http middleware that logs request content and key values after processing.
func RequestLogger(keys []string, contentKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Wrap the response to capture status code if needed
			lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Call the next handler
			next.ServeHTTP(lrw, r)

			// Log only for non-GET and successful responses (status < 400)
			if r.Method != http.MethodGet && lrw.statusCode < 400 {
				ctx := r.Context()

				// Get contentKey value (e.g., JSON body or structured data)
				data := ctx.Value(contextKey(contentKey))
				if data != nil {
					values := make([]string, 0, len(keys))
					for _, key := range keys {
						val := ctx.Value(contextKey(key))
						if str, ok := val.(string); ok {
							values = append(values, str)
						}
					}
					slog.Info("gokeycloakauth request", "data", data, "keys", strings.Join(values, "-"))
				}
			}
		})
	}
}

// A simple response writer wrapper to capture the status code.
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}
