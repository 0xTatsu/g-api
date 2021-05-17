package jwt

import (
	"context"
	"net/http"

	"github.com/0xTatsu/mvtn-api/handler/res"
	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/jwt"
	"go.uber.org/zap"
)

const (
	ctxAccessClaimsKey  = "ctxAccessClaimsKey"
	ctxRefreshClaimsKey = "ctxRefreshClaimsKey"
)

// ClaimsFromCtx retrieves the parsed AccessClaims from request context.
func ClaimsFromCtx(ctx context.Context) AccessClaims {
	return ctx.Value(ctxAccessClaimsKey).(AccessClaims)
}

// RefreshClaimsFromCtx retrieves the parsed refresh token from context.
func RefreshClaimsFromCtx(ctx context.Context) RefreshClaims {
	return ctx.Value(ctxRefreshClaimsKey).(RefreshClaims)
}

func Authenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, claims, err := jwtauth.FromContext(r.Context())
		if err != nil || token == nil {
			res.Error(w, r, http.StatusUnauthorized, "No token found")
			return
		}

		if err := jwt.Validate(token); err != nil {
			res.Error(w, r, http.StatusUnauthorized, err.Error())
			return
		}

		// Token is authenticated, parse claims
		var accessClaims AccessClaims
		err = accessClaims.ParseClaims(claims)
		if err != nil {
			zap.L().Error("cannot parse claims", zap.Error(err))
			res.Error(w, r, http.StatusUnauthorized, ErrInvalidAccessToken.Error())
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
			res.Error(w, r, http.StatusUnauthorized, ErrInvalidRefreshToken.Error())
			return
		}

		// Set refresh token string on context
		ctx := context.WithValue(r.Context(), ctxRefreshClaimsKey, c)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
