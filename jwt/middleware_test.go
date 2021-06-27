package jwt_test

import (
	"context"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0xTatsu/g-api/config"
	"github.com/0xTatsu/g-api/jwt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	jwxJWT "github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const jwtSecret = "not-secret"

var ErrTest = errors.New("err test")

func TestAuthenticator(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	t.Run("throw error if get token from context fails", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx := context.WithValue(context.TODO(), jwtauth.ErrorCtxKey, ErrTest)
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, "/test", nil)
		require.NoError(t, err)
		handler(w, r)

		next := jwt.Authenticator(handler)
		next.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "Unauthorized\n", w.Body.String())
	})

	t.Run("throw error if parse access claims fails", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx := context.WithValue(context.TODO(), jwtauth.TokenCtxKey, 123)
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, "/test", nil)
		require.NoError(t, err)
		handler(w, r)

		next := jwt.Authenticator(handler)
		next.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "Unauthorized\n", w.Body.String())
	})

	t.Run("if succeeds, pass claims to a new context", func(t *testing.T) {
		envCfg := config.Configs{JwtSecret: jwtSecret}
		authJWT := jwt.NewJWT(&envCfg)
		claims := map[string]interface{}{"id": uint(31337), "roles": []string{"user"}}

		r := chi.NewRouter()
		r.Use(authJWT.Verifier())
		r.Use(jwt.Authenticator)
		r.Get("/test", func(w http.ResponseWriter, r *http.Request) {
			accessClaims, ok := r.Context().Value(jwt.AccessClaimCtxKey).(jwt.AccessClaims)
			assert.True(t, ok)
			assert.Equal(t, claims["id"], accessClaims.ID)
			assert.Equal(t, claims["roles"], accessClaims.Roles)
		})

		ts := httptest.NewServer(r)
		defer ts.Close()

		statusCode, bodyString := testRequest(t, ts, "GET", "/test", newAuthHeader(claims), nil)
		assert.Equal(t, statusCode, http.StatusOK)
		assert.Empty(t, bodyString)
	})
}

func newJwtToken(secret []byte, claims ...map[string]interface{}) string {
	token := jwxJWT.New()
	if len(claims) > 0 {
		for k, v := range claims[0] {
			_ = token.Set(k, v)
		}
	}
	tokenPayload, err := jwxJWT.Sign(token, "HS256", secret)
	if err != nil {
		log.Fatal(err)
	}
	return string(tokenPayload)
}

func newAuthHeader(claims map[string]interface{}) http.Header {
	h := http.Header{}
	h.Set("Authorization", "BEARER "+newJwtToken([]byte(jwtSecret), claims))
	return h
}

func testRequest(t *testing.T, ts *httptest.Server, method, path string, header http.Header, body io.Reader) (int, string) {
	t.Helper()

	req, err := http.NewRequest(method, ts.URL+path, body)
	if err != nil {
		t.Fatal(err)
		return 0, ""
	}

	for k, v := range header {
		req.Header.Set(k, v[0])
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
		return 0, ""
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
		return 0, ""
	}
	defer resp.Body.Close()

	return resp.StatusCode, string(respBody)
}
