package jwt

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/lestrrat-go/jwx/jwt"
	"go.uber.org/zap"

	"github.com/0xTatsu/mvtn-api/config"
)

type ctxKey int

const (
	ctxClaims ctxKey = iota
	ctxRefreshToken
)

// ClaimsFromCtx retrieves the parsed AppClaims from request context.
func ClaimsFromCtx(ctx context.Context) AppClaims {
	return ctx.Value(ctxClaims).(AppClaims)
}

// RefreshTokenFromCtx retrieves the parsed refresh token from context.
func RefreshTokenFromCtx(ctx context.Context) string {
	return ctx.Value(ctxRefreshToken).(string)
}

type AuthJWT struct {
	cfg     *config.Configuration
	jwtAuth *jwtauth.JWTAuth
}

func NewJWT(
	cfg *config.Configuration,
) *AuthJWT {
	return &AuthJWT{
		cfg:     cfg,
		jwtAuth: jwtauth.New("HS256", []byte(cfg.JWT.Secret), nil),
	}
}

// CreateJWT returns an access token for provided account claims.
func (a *AuthJWT) CreateJWT(c AppClaims) (string, error) {
	c.IssuedAt = time.Now().Unix()
	c.ExpiresAt = time.Now().Add(time.Hour * time.Duration(a.cfg.JWT.ExpiryInHour)).Unix()

	_, tokenString, err := a.jwtAuth.Encode(ToMapStringInterface(c))

	return tokenString, err
}

// CreateRefreshJWT returns a refresh token for provided token Claims.
func (a *AuthJWT) CreateRefreshJWT(c RefreshClaims) (string, error) {
	c.IssuedAt = time.Now().Unix()
	c.ExpiresAt = time.Now().Add(time.Hour * time.Duration(a.cfg.JWT.RefreshExpiryInHour)).Unix()

	_, tokenString, err := a.jwtAuth.Encode(ToMapStringInterface(c))

	return tokenString, err
}

// Verifier http middleware will verify a jwt string from a http request.
func (a *AuthJWT) Verifier() func(http.Handler) http.Handler {
	return jwtauth.Verifier(a.jwtAuth)
}

func Authenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, claims, err := jwtauth.FromContext(r.Context())

		if err != nil || token == nil {
			render.JSON(w, r, ErrUnauthorized(ErrTokenUnauthorized))
			return
		}

		if err := jwt.Validate(token); err != nil {
			render.JSON(w, r, ErrUnauthorized(err))
			return
		}

		// Token is authenticated, parse claims
		var c AppClaims
		err = c.ParseClaims(claims)
		if err != nil {
			zap.L().Error("cannot parse claims", zap.Error(err))
			render.JSON(w, r, ErrUnauthorized(ErrInvalidAccessToken))
			return
		}

		// Set AppClaims on context
		ctx := context.WithValue(r.Context(), ctxClaims, c)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AuthenticateRefreshJWT checks validity of refresh tokens and is only used for access token refresh and logout requests. It responds with 401 Unauthorized for invalid or expired refresh tokens.
func AuthenticateRefreshJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, claims, err := jwtauth.FromContext(r.Context())

		if err != nil || token == nil {
			render.JSON(w, r, ErrUnauthorized(ErrTokenUnauthorized))
			return
		}

		if err := jwt.Validate(token); err != nil {
			zap.L().Error("validate token fails", zap.Error(err))
			render.JSON(w, r, ErrUnauthorized(err))
			return
		}

		// Token is authenticated, parse refresh token string
		var c RefreshClaims
		err = c.ParseClaims(claims)
		if err != nil {
			zap.L().Error("parse token fails", zap.Error(err))
			render.JSON(w, r, ErrUnauthorized(ErrInvalidRefreshToken))
			return
		}

		// Set refresh token string on context
		ctx := context.WithValue(r.Context(), ctxRefreshToken, c.Token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func ToMapStringInterface(c interface{}) map[string]interface{} {
	m := make(map[string]interface{})

	j, err := json.Marshal(c)
	if err != nil {
		zap.L().Error("cannot marshal", zap.Error(err))
	}

	if err := json.Unmarshal(j, &m); err != nil {
		zap.L().Error("cannot marshal", zap.Error(err))
	}

	return m
}
