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

var app = model.App{
	Cfg: &config.Configuration{
		JWT: &config.JWT{
			Secret:              "",
			HttpCookieKey:       "token",
			ExpiryInHour:        24,
			RefreshExpiryInHour: 25 * 30,
		},
	},
	Validator: appValidator.New(validator.New()),
}

func Test_Register(t *testing.T) {
	ctx := context.TODO()
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
		errs := test.Body2Errors(t, res.Body)
		assert.Len(t, errs, 2)
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

func Test_Login(t *testing.T) {
	ctx := context.TODO()
	authJWT := jwt.NewJWT(app.Cfg)

	t.Run("if request validation fails, return errors", func(t *testing.T) {
		res := httptest.NewRecorder()
		var body = []byte(`{"email": "abc@", "password":""}`)
		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		require.NoError(t, err)

		accountRepo := &mocks.AccountRepo{}
		authHandler := handler.NewAuth(&app, authJWT, accountRepo)
		authHandler.Login(res, req)
		assert.Equal(t, http.StatusBadRequest, res.Code)
		errs := test.Body2Errors(t, res.Body)
		assert.Len(t, errs, 2)
		accountRepo.AssertNotCalled(t, "GetByEmail")
	})

	t.Run("if get account by email fails, return error", func(t *testing.T) {
		res := httptest.NewRecorder()
		var body = []byte(`{"email": "abc@gmail.com", "password":"12345678"}`)
		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		require.NoError(t, err)

		accountRepo := &mocks.AccountRepo{}
		accountRepo.On("GetByEmail", ctx, "abc@gmail.com").Return(nil, test.ErrTest)
		authHandler := handler.NewAuth(&app, authJWT, accountRepo)
		authHandler.Login(res, req)

		assert.Equal(t, http.StatusInternalServerError, res.Code)
		accountRepo.AssertExpectations(t)
	})

	t.Run("if password is incorrect return unauthorized", func(t *testing.T) {
		res := httptest.NewRecorder()
		var body = []byte(`{"email": "abc@gmail.com", "password":"12345678"}`)
		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		require.NoError(t, err)

		account := &model.Account{Password: ""}
		accountRepo := &mocks.AccountRepo{}
		accountRepo.On("GetByEmail", ctx, "abc@gmail.com").Return(account, nil)
		authHandler := handler.NewAuth(&app, authJWT, accountRepo)
		authHandler.Login(res, req)

		assert.Equal(t, http.StatusUnauthorized, res.Code)
		accountRepo.AssertExpectations(t)
	})

	t.Run("if account is not allow to login, return unauthorized", func(t *testing.T) {
		res := httptest.NewRecorder()
		var body = []byte(`{"email": "abc@gmail.com", "password":"12345678"}`)
		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		require.NoError(t, err)

		account := &model.Account{Password: "$2a$10$/O5r9A49M0ewJjsXvoh7dOzF.OdazGXYi/qTf/b3.u6zOk0JQv4U.", Active: false}
		accountRepo := &mocks.AccountRepo{}
		accountRepo.On("GetByEmail", ctx, "abc@gmail.com").Return(account, nil)
		authHandler := handler.NewAuth(&app, authJWT, accountRepo)
		authHandler.Login(res, req)

		assert.Equal(t, http.StatusUnauthorized, res.Code)
		accountRepo.AssertExpectations(t)
	})

	t.Run("if create token pair fails, return internal error", func(t *testing.T) {
		res := httptest.NewRecorder()
		var body = []byte(`{"email": "abc@gmail.com", "password":"12345678"}`)
		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		require.NoError(t, err)

		account := &model.Account{
			Password: "$2a$10$/O5r9A49M0ewJjsXvoh7dOzF.OdazGXYi/qTf/b3.u6zOk0JQv4U.",
			Active:   true,
		}
		accountRepo := &mocks.AccountRepo{}
		accountRepo.On("GetByEmail", ctx, "abc@gmail.com").Return(account, nil)
		authHandler := handler.NewAuth(&app, authJWT, accountRepo)
		authHandler.Login(res, req)

		assert.Equal(t, http.StatusInternalServerError, res.Code)
		accountRepo.AssertExpectations(t)
	})

	t.Run("if update account fails, return internal error", func(t *testing.T) {
		res := httptest.NewRecorder()
		var body = []byte(`{"email": "abc@gmail.com", "password":"12345678"}`)
		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		require.NoError(t, err)

		account := &model.Account{
			ID:       1,
			Roles:    []string{model.RoleUser},
			Password: "$2a$10$/O5r9A49M0ewJjsXvoh7dOzF.OdazGXYi/qTf/b3.u6zOk0JQv4U.",
			Active:   true,
		}
		accountRepo := &mocks.AccountRepo{}
		accountRepo.On("GetByEmail", ctx, "abc@gmail.com").Return(account, nil)
		accountRepo.On("Update", ctx, account).Return(test.ErrTest)
		app.Cfg.JWT.Secret = "not so secret"
		authJWT := jwt.NewJWT(app.Cfg)
		authHandler := handler.NewAuth(&app, authJWT, accountRepo)
		authHandler.Login(res, req)

		assert.Equal(t, http.StatusInternalServerError, res.Code)
		accountRepo.AssertExpectations(t)
	})

	t.Run("if login succeeds, return account data with tokens", func(t *testing.T) {
		res := httptest.NewRecorder()
		var body = []byte(`{"email": "abc@gmail.com", "password":"12345678"}`)
		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		require.NoError(t, err)

		account := &model.Account{
			ID:       1,
			Roles:    []string{model.RoleUser},
			Password: "$2a$10$/O5r9A49M0ewJjsXvoh7dOzF.OdazGXYi/qTf/b3.u6zOk0JQv4U.",
			Active:   true,
		}
		accountRepo := &mocks.AccountRepo{}
		accountRepo.On("GetByEmail", ctx, "abc@gmail.com").Return(account, nil)
		accountRepo.On("Update", ctx, account).Return(nil)
		app.Cfg.JWT.Secret = "not so secret"
		authJWT := jwt.NewJWT(app.Cfg)
		authHandler := handler.NewAuth(&app, authJWT, accountRepo)
		authHandler.Login(res, req)

		assert.Equal(t, http.StatusOK, res.Code)
		items := test.Body2Items(t, res.Body)

		assert.NoError(t, err)
		assert.Equal(t, float64(1), items[0]["id"])
		assert.NotEmpty(t, items[0]["access_token"])
		assert.NotEmpty(t, items[0]["refresh_token"])

		accountRepo.AssertExpectations(t)
	})
}
