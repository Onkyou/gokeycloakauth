package keycloakauth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc"
)

type contextKey string

const UserContextKey contextKey = "user"

type Config struct {
	IssuerURL string
	ClientID  string
}

type Middleware struct {
	verifier *oidc.IDTokenVerifier
}

func New(cfg Config) (*Middleware, error) {
	provider, err := oidc.NewProvider(context.Background(), cfg.IssuerURL)
	if err != nil {
		return nil, err
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	return &Middleware{
		verifier: verifier,
	}, nil
}

func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}

		token := extractBearerToken(authHeader)
		if token == "" {
			http.Error(w, "invalid Authorization format", http.StatusUnauthorized)
			return
		}

		idToken, err := m.verifier.Verify(r.Context(), token)
		if err != nil {
			http.Error(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		var claims map[string]interface{}
		if err := idToken.Claims(&claims); err != nil {
			http.Error(w, "invalid claims", http.StatusInternalServerError)
			return
		}

		ctx := context.WithValue(r.Context(), UserContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetUserClaims(ctx context.Context) (map[string]interface{}, error) {
	claims, ok := ctx.Value(UserContextKey).(map[string]interface{})
	if !ok {
		return nil, errors.New("no user claims in context")
	}
	return claims, nil
}

func extractBearerToken(header string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}
