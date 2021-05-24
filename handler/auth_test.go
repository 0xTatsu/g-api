package handler_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xTatsu/mvtn-api/config"
	"github.com/0xTatsu/mvtn-api/handler"
	appValidator "github.com/0xTatsu/mvtn-api/handler/validator"
	"github.com/0xTatsu/mvtn-api/jwt"
	"github.com/0xTatsu/mvtn-api/model"
	"github.com/0xTatsu/mvtn-api/repo/mocks"
	"github.com/0xTatsu/mvtn-api/test"
)

func Test_Register(t *testing.T) {
	app := model.App{
		Cfg: &config.Configuration{
			JWT: &config.JWT{
				Secret:              "",
				HttpCookieKey:       "",
				ExpiryInHour:        0,
				RefreshExpiryInHour: 0,
			},
		},
		Validator: appValidator.New(validator.New()),
	}
	authJWT := jwt.NewJWT(app.Cfg)

	t.Run("empty request body will return error", func(t *testing.T) {
		res := httptest.NewRecorder()
		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(nil))
		require.NoError(t, err)

		accountRepo := &mocks.AccountRepo{}
		authHandler := handler.NewAuth(&app, authJWT, accountRepo)
		authHandler.Register(res, req)

		assert.Equal(t, http.StatusBadRequest, res.Code)
	})

	t.Run("invalid request body", func(t *testing.T) {
		res := httptest.NewRecorder()
		var body = []byte(`{}`)
		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		require.NoError(t, err)

		accountRepo := &mocks.AccountRepo{}
		authHandler := handler.NewAuth(&app, authJWT, accountRepo)
		authHandler.Register(res, req)

		assert.Equal(t, http.StatusBadRequest, res.Code)
		resp := test.Body2Response(t, res.Body)
		assert.Len(t, resp.Error.Errors, 2)
	})
}
