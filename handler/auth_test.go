package handler_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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
	ctx := context.TODO()
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

	t.Run("if request validation fails, return errors", func(t *testing.T) {
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
		accountRepo.AssertNotCalled(t, "Create")
	})

	t.Run("if creating account fails, return error", func(t *testing.T) {
		res := httptest.NewRecorder()
		var body = []byte(`{"email":"abc@gmail.com", "password":"12345678", "confirm_password":"12345678"}`)
		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		require.NoError(t, err)

		accountRepo := &mocks.AccountRepo{}
		accountRepo.On("Create", ctx, mock.Anything).Return(nil, test.ErrTest)
		authHandler := handler.NewAuth(&app, authJWT, accountRepo)
		authHandler.Register(res, req)

		assert.Equal(t, http.StatusInternalServerError, res.Code)
		resp := test.Body2Response(t, res.Body)
		assert.Equal(t, http.StatusText(http.StatusInternalServerError), resp.Message)
		accountRepo.AssertExpectations(t)
	})

	t.Run("if creating account succeeds, status will be 201", func(t *testing.T) {
		res := httptest.NewRecorder()
		var body = []byte(`{"email":"abc@gmail.com", "password":"12345678", "confirm_password":"12345678"}`)
		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		require.NoError(t, err)

		accountRepo := &mocks.AccountRepo{}
		accountRepo.On("Create", ctx, mock.Anything).Run(func(args mock.Arguments) {
			actualData, ok := args.Get(1).(*model.Account)
			if assert.True(t, ok) {
				assert.Equal(t, "abc@gmail.com", actualData.Email)
				assert.Equal(t, model.RoleUser, actualData.Roles[0])
				assert.True(t, actualData.Active)
				assert.NotEmpty(t, actualData.Password)
			}
		}).Return(nil, nil)
		authHandler := handler.NewAuth(&app, authJWT, accountRepo)
		authHandler.Register(res, req)

		assert.Equal(t, http.StatusCreated, res.Code)
		accountRepo.AssertExpectations(t)
	})
}
