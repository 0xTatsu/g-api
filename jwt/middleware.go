package jwt

import (
	"context"
	"net/http"

	"github.com/go-chi/jwtauth/v5"
	"go.uber.org/zap"
)

var (
	AccessClaimCtxKey  = &contextKey{"AccessClaimCtxKey"}
	RefreshClaimCtxKey = &contextKey{"RefreshClaimCtxKey"}
)

type contextKey struct {
	name string
}

func (k *contextKey) String() string {
	return "g-api context value " + k.name
}

func Authenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, claims, err := jwtauth.FromContext(r.Context())
		if err != nil {
			zap.L().Error("cannot get token from context", zap.Error(jwtauth.ErrorReason(err)))
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// Token is authenticated, parse claims
		var accessClaims AccessClaims
		err = accessClaims.ParseClaims(claims)
		if err != nil {
			zap.L().Error("cannot parse AccessClaims", zap.Error(err))
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// Set AccessClaims on context
		ctx := context.WithValue(r.Context(), AccessClaimCtxKey, accessClaims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AuthenticateRefreshJWT checks validity of refresh tokens and is only used for access token refresh and logout requests. It responds with 401 Unauthorized for invalid or expired refresh tokens.
func AuthenticateRefreshJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, claims, err := jwtauth.FromContext(r.Context())
		if err != nil {
			http.Error(w, jwtauth.ErrorReason(err).Error(), http.StatusUnauthorized)
			return
		}

		// Token is authenticated, parse refresh token string
		var c RefreshClaims
		err = c.ParseClaims(claims)
		if err != nil {
			zap.L().Error("cannot parse RefreshClaims", zap.Error(err))
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// Set refresh token string on context
		ctx := context.WithValue(r.Context(), RefreshClaimCtxKey, c)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
