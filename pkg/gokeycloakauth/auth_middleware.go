package gokeycloakauth

import "net/http"

func AuthMiddleware(config KeycloakConfig, accessFn AccessCheckFunction, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenContainer, ok := getTokenContainer(r, config)
		if !ok || !tokenContainer.Valid() {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if !accessFn(tokenContainer, r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r.WithContext(r.Context()))
	})
}
