package gokeycloakauth

import (
	"log/slog"
	"net/http"
)

type BuilderConfig struct {
	Service              string
	Url                  string
	Realm                string
	FullCertsPath        *string
	DisableSecurityCheck bool
	HTTPClient           *http.Client
}

type RestrictedAccessBuilder interface {
	RestrictButForRole(role string) RestrictedAccessBuilder
	RestrictButForUid(uid string) RestrictedAccessBuilder
	RestrictButForRealm(realmName string) RestrictedAccessBuilder
	Build() func(http.Handler) http.Handler
}

type restrictedAccessBuilderImpl struct {
	allowedRoles  []AccessTuple
	allowedUids   []AccessTuple
	allowedRealms []string
	config        BuilderConfig
}

func NewAccessBuilder(config BuilderConfig) RestrictedAccessBuilder {
	return &restrictedAccessBuilderImpl{
		config:       config,
		allowedRoles: []AccessTuple{},
	}
}

func (b *restrictedAccessBuilderImpl) RestrictButForRole(role string) RestrictedAccessBuilder {
	b.allowedRoles = append(b.allowedRoles, AccessTuple{Service: b.config.Service, Role: role})
	return b
}

func (b *restrictedAccessBuilderImpl) RestrictButForUid(uid string) RestrictedAccessBuilder {
	b.allowedUids = append(b.allowedUids, AccessTuple{Service: b.config.Service, Uid: uid})
	return b
}

func (b *restrictedAccessBuilderImpl) RestrictButForRealm(realmName string) RestrictedAccessBuilder {
	b.allowedRealms = append(b.allowedRealms, realmName)
	return b
}

func (b *restrictedAccessBuilderImpl) Build() func(http.Handler) http.Handler {
	accessFn := func(tc *TokenContainer, r *http.Request) bool { return true }
	if b.config.DisableSecurityCheck {
		slog.Warn("gokeycloakauth access check is disabled")
	} else {
		accessFn = b.checkIfOneConditionMatches()
	}
	config := KeycloakConfig{
		Url:           b.config.Url,
		Realm:         b.config.Realm,
		FullCertsPath: b.config.FullCertsPath,
		HTTPClient:    b.config.HTTPClient,
	}

	return Auth(config, accessFn)
}

func (b *restrictedAccessBuilderImpl) checkIfOneConditionMatches() AccessCheckFunction {
	return func(tc *TokenContainer, r *http.Request) bool {
		return GroupCheck(b.allowedRoles)(tc, r) ||
			UidCheck(b.allowedUids)(tc, r) ||
			RealmCheck(b.allowedRealms)(tc, r)
	}
}
