package jwt_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0xTatsu/g-api/jwt"
	"github.com/go-chi/jwtauth/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var ErrTest = errors.New("err test")

func TestAuthenticator(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	t.Run("throw error if get token from context fails", func(t *testing.T) {
		ctx := context.WithValue(context.TODO(), jwtauth.ErrorCtxKey, ErrTest)
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, "/test", nil)
		require.NoError(t, err)
		w := httptest.NewRecorder()
		handler(w, r)

		next := jwt.Authenticator(handler)
		next.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "Unauthorized\n", w.Body.String())
	})

	t.Run("throw error if parse access claims fails", func(t *testing.T) {
		ctx := context.WithValue(context.TODO(), jwtauth.TokenCtxKey, 123)
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, "/test", nil)
		require.NoError(t, err)
		w := httptest.NewRecorder()
		handler(w, r)

		next := jwt.Authenticator(handler)
		next.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "Unauthorized\n", w.Body.String())
	})

	// t.Run("if succeeds, pass claims to a new context", func(t *testing.T) {
	// 	w := httptest.NewRecorder()
	// 	r := httptest.NewRequest(http.MethodGet, "/test", nil)
	// 	r.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MjQyOTA1NTIsImlhdCI6MTYyNDIwNDE1MiwiaWQiOjEsInJvbGVzIjpbInVzZXIiXX0.pLBrJVqZVWLig2YU78OU6gXsEb_B5YsO6eIsDuyPCoE")
	// 	handler(w, r)
	//
	// 	next := jwt.Authenticator(handler)
	// 	next.ServeHTTP(w, r)
	//
	// 	assert.Equal(t, http.StatusOK, w.Code)
	// 	// assert.Equal(t, "Unauthorized\n", w.Body.String())
	// })
}
