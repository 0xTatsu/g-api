package jwt

import (
	"context"
	"net/http"

	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/jwt"
	"go.uber.org/zap"

	"github.com/0xTatsu/g-api/handler/res"
)

const (
	ctxAccessClaimsKey  = "ctxAccessClaimsKey"
	ctxRefreshClaimsKey = "ctxRefreshClaimsKey"
)

func Authenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, claims, err := jwtauth.FromContext(r.Context())
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		if token == nil {
			http.Error(w, jwtauth.ErrNoTokenFound.Error(), http.StatusUnauthorized)
			return
		}

		if err := jwt.Validate(token); err != nil {
			res.Unauthorized(w, r)
			return
		}

		// Token is authenticated, parse claims
		var accessClaims AccessClaims
		err = accessClaims.ParseClaims(claims)
		if err != nil {
			zap.L().Error("cannot parse claims", zap.Error(err))
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// Set AccessClaims on context
		ctx := context.WithValue(r.Context(), ctxAccessClaimsKey, accessClaims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AuthenticateRefreshJWT checks validity of refresh tokens and is only used for access token refresh and logout requests. It responds with 401 Unauthorized for invalid or expired refresh tokens.
func AuthenticateRefreshJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, claims, err := jwtauth.FromContext(r.Context())

		// Token is authenticated, parse refresh token string
		var c RefreshClaims
		err = c.ParseClaims(claims)
		if err != nil {
			zap.L().Error("parse token fails", zap.Error(err))
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// Set refresh token string on context
		ctx := context.WithValue(r.Context(), ctxRefreshClaimsKey, c)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
