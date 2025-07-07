package gokeycloakauth

import (
	"context"
	"net/http"
)

type ctxKey string

const (
	keyToken ctxKey = "keycloak_token"
	keyUID   ctxKey = "keycloak_uid"
)

type AccessCheckFunction func(tc *TokenContainer, r *http.Request) bool

type AccessTuple struct {
	Service string
	Role    string
	Uid     string
}

// ---- Access check helpers ----

func GroupCheck(ats []AccessTuple) AccessCheckFunction {
	return func(tc *TokenContainer, r *http.Request) bool {
		r = addTokenToRequest(tc, r)
		for _, at := range ats {
			if tc.KeyCloakToken.ResourceAccess != nil {
				serviceRoles := tc.KeyCloakToken.ResourceAccess[at.Service]
				for _, role := range serviceRoles.Roles {
					if role == at.Role {
						return true
					}
				}
			}
		}
		return false
	}
}

func RealmCheck(allowedRoles []string) AccessCheckFunction {
	return func(tc *TokenContainer, r *http.Request) bool {
		r = addTokenToRequest(tc, r)
		for _, allowed := range allowedRoles {
			for _, role := range tc.KeyCloakToken.RealmAccess.Roles {
				if role == allowed {
					return true
				}
			}
		}
		return false
	}
}

func UidCheck(ats []AccessTuple) AccessCheckFunction {
	return func(tc *TokenContainer, r *http.Request) bool {
		r = addTokenToRequest(tc, r)
		uid := tc.KeyCloakToken.PreferredUsername
		for _, at := range ats {
			if at.Uid == uid {
				return true
			}
		}
		return false
	}
}

func AuthCheck() AccessCheckFunction {
	return func(tc *TokenContainer, r *http.Request) bool {
		r = addTokenToRequest(tc, r)
		return true
	}
}

func addTokenToRequest(tc *TokenContainer, r *http.Request) *http.Request {
	ctx := context.WithValue(r.Context(), keyToken, tc.KeyCloakToken)
	ctx = context.WithValue(ctx, keyUID, tc.KeyCloakToken.PreferredUsername)
	return r.WithContext(ctx)
}

func GetToken(r *http.Request) (*KeyCloakToken, bool) {
	tok, ok := r.Context().Value(keyToken).(*KeyCloakToken)
	return tok, ok
}

func GetUID(r *http.Request) (string, bool) {
	uid, ok := r.Context().Value(keyUID).(string)
	return uid, ok
}
