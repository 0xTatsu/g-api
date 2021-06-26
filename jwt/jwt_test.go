package jwt_test

import (
	"testing"

	"github.com/0xTatsu/g-api/config"
	"github.com/0xTatsu/g-api/jwt"
	"github.com/stretchr/testify/assert"
)

func TestJWT(t *testing.T) {
	t.Run("CreateAccessToken succeeds", func(t *testing.T) {
		accessClaims := jwt.AccessClaims{ID: uint(1), Roles: []string{"user"}}
		envCfg := config.Env{JwtSecret: jwtSecret}
		authJWT := jwt.NewJWT(&envCfg)
		tokenString, err := authJWT.CreateAccessToken(accessClaims)
		assert.NoError(t, err)
		assert.NotEmpty(t, tokenString)
	})

	t.Run("CreateRefreshToken succeeds", func(t *testing.T) {
		refreshClaims := jwt.RefreshClaims{ID: uint(1)}
		envCfg := config.Env{JwtSecret: jwtSecret}
		authJWT := jwt.NewJWT(&envCfg)
		tokenString, err := authJWT.CreateRefreshToken(refreshClaims)
		assert.NoError(t, err)
		assert.NotEmpty(t, tokenString)
	})

	t.Run("CreateTokenPair succeeds", func(t *testing.T) {
		accessClaims := jwt.AccessClaims{ID: uint(1), Roles: []string{"user"}}
		refreshClaims := jwt.RefreshClaims{ID: uint(1)}
		envCfg := config.Env{JwtSecret: jwtSecret}
		authJWT := jwt.NewJWT(&envCfg)
		accessToken, refreshToken, err := authJWT.CreateTokenPair(accessClaims, refreshClaims)
		assert.NoError(t, err)
		assert.NotEmpty(t, accessToken)
		assert.NotEmpty(t, refreshToken)
	})

	t.Run("No Secret provided, CreateTokenPair fails", func(t *testing.T) {
		accessClaims := jwt.AccessClaims{ID: uint(1), Roles: []string{"user"}}
		refreshClaims := jwt.RefreshClaims{ID: uint(1)}
		envCfg := config.Env{}
		authJWT := jwt.NewJWT(&envCfg)
		accessToken, refreshToken, err := authJWT.CreateTokenPair(accessClaims, refreshClaims)
		assert.Error(t, err)
		assert.Empty(t, accessToken)
		assert.Empty(t, refreshToken)
	})

	t.Run("ToMapStringInterface", func(t *testing.T) {
		res := jwt.ToMapStringInterface(map[string]interface{}{"a": "b"})
		assert.NotNil(t, res)
		assert.Equal(t, "b", res["a"])
	})
}
