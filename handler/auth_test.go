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

	"github.com/0xTatsu/g-api/config"
	"github.com/0xTatsu/g-api/handler"
	appValidator "github.com/0xTatsu/g-api/handler/validator"
	"github.com/0xTatsu/g-api/jwt"
	"github.com/0xTatsu/g-api/model"
	"github.com/0xTatsu/g-api/repo/mocks"
	"github.com/0xTatsu/g-api/test"
)

var app = model.App{
	Cfg: &config.Configuration{
		JwtSecret:              "",
		JwtHttpCookieKey:       "token",
		JwtExpiryInHour:        24,
		JwtRefreshExpiryInHour: 25 * 30,
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

		userRepo := &mocks.UserRepo{}
		authHandler := handler.NewAuth(&app, authJWT, userRepo)
		authHandler.Register(res, req)

		assert.Equal(t, http.StatusBadRequest, res.Code)
		errs := test.Body2Errors(t, res.Body)
		assert.Len(t, errs, 2)
		userRepo.AssertNotCalled(t, "Create")
	})

	t.Run("if creating user fails, return error", func(t *testing.T) {
		res := httptest.NewRecorder()
		var body = []byte(`{"email":"abc@gmail.com", "password":"12345678", "confirm_password":"12345678"}`)
		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		require.NoError(t, err)

		userRepo := &mocks.UserRepo{}
		userRepo.On("Create", ctx, mock.Anything).Return(nil, test.ErrTest)
		authHandler := handler.NewAuth(&app, authJWT, userRepo)
		authHandler.Register(res, req)

		assert.Equal(t, http.StatusInternalServerError, res.Code)
		userRepo.AssertExpectations(t)
	})

	t.Run("if creating user succeeds, status will be 201", func(t *testing.T) {
		res := httptest.NewRecorder()
		var body = []byte(`{"email":"abc@gmail.com", "password":"12345678", "confirm_password":"12345678"}`)
		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		require.NoError(t, err)

		userRepo := &mocks.UserRepo{}
		userRepo.On("Create", ctx, mock.Anything).Run(func(args mock.Arguments) {
			actualData, ok := args.Get(1).(*model.User)
			if assert.True(t, ok) {
				assert.Equal(t, "abc@gmail.com", actualData.Email)
				assert.Equal(t, model.RoleUser, actualData.Roles[0])
				assert.True(t, actualData.Active)
				assert.NotEmpty(t, actualData.Password)
			}
		}).Return(nil, nil)
		authHandler := handler.NewAuth(&app, authJWT, userRepo)
		authHandler.Register(res, req)

		assert.Equal(t, http.StatusCreated, res.Code)
		userRepo.AssertExpectations(t)
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

		userRepo := &mocks.UserRepo{}
		authHandler := handler.NewAuth(&app, authJWT, userRepo)
		authHandler.Login(res, req)
		assert.Equal(t, http.StatusBadRequest, res.Code)
		errs := test.Body2Errors(t, res.Body)
		assert.Len(t, errs, 2)
		userRepo.AssertNotCalled(t, "GetByEmail")
	})

	t.Run("if get user by email fails, return error", func(t *testing.T) {
		res := httptest.NewRecorder()
		var body = []byte(`{"email": "abc@gmail.com", "password":"12345678"}`)
		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		require.NoError(t, err)

		userRepo := &mocks.UserRepo{}
		userRepo.On("GetByEmail", ctx, "abc@gmail.com").Return(nil, test.ErrTest)
		authHandler := handler.NewAuth(&app, authJWT, userRepo)
		authHandler.Login(res, req)

		assert.Equal(t, http.StatusInternalServerError, res.Code)
		userRepo.AssertExpectations(t)
	})

	t.Run("if password is incorrect return unauthorized", func(t *testing.T) {
		res := httptest.NewRecorder()
		var body = []byte(`{"email": "abc@gmail.com", "password":"12345678"}`)
		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		require.NoError(t, err)

		user := &model.User{Password: ""}
		userRepo := &mocks.UserRepo{}
		userRepo.On("GetByEmail", ctx, "abc@gmail.com").Return(user, nil)
		authHandler := handler.NewAuth(&app, authJWT, userRepo)
		authHandler.Login(res, req)

		assert.Equal(t, http.StatusUnauthorized, res.Code)
		userRepo.AssertExpectations(t)
	})

	t.Run("if user is not allow to login, return unauthorized", func(t *testing.T) {
		res := httptest.NewRecorder()
		var body = []byte(`{"email": "abc@gmail.com", "password":"12345678"}`)
		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		require.NoError(t, err)

		user := &model.User{Password: "$2a$10$/O5r9A49M0ewJjsXvoh7dOzF.OdazGXYi/qTf/b3.u6zOk0JQv4U.", Active: false}
		userRepo := &mocks.UserRepo{}
		userRepo.On("GetByEmail", ctx, "abc@gmail.com").Return(user, nil)
		authHandler := handler.NewAuth(&app, authJWT, userRepo)
		authHandler.Login(res, req)

		assert.Equal(t, http.StatusUnauthorized, res.Code)
		userRepo.AssertExpectations(t)
	})

	t.Run("if create token pair fails, return internal error", func(t *testing.T) {
		res := httptest.NewRecorder()
		var body = []byte(`{"email": "abc@gmail.com", "password":"12345678"}`)
		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		require.NoError(t, err)

		user := &model.User{
			Password: "$2a$10$/O5r9A49M0ewJjsXvoh7dOzF.OdazGXYi/qTf/b3.u6zOk0JQv4U.",
			Active:   true,
		}
		userRepo := &mocks.UserRepo{}
		userRepo.On("GetByEmail", ctx, "abc@gmail.com").Return(user, nil)
		authHandler := handler.NewAuth(&app, authJWT, userRepo)
		authHandler.Login(res, req)

		assert.Equal(t, http.StatusInternalServerError, res.Code)
		userRepo.AssertExpectations(t)
	})

	t.Run("if update user fails, return internal error", func(t *testing.T) {
		res := httptest.NewRecorder()
		var body = []byte(`{"email": "abc@gmail.com", "password":"12345678"}`)
		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		require.NoError(t, err)

		user := &model.User{
			ID:       1,
			Roles:    []string{model.RoleUser},
			Password: "$2a$10$/O5r9A49M0ewJjsXvoh7dOzF.OdazGXYi/qTf/b3.u6zOk0JQv4U.",
			Active:   true,
		}
		userRepo := &mocks.UserRepo{}
		userRepo.On("GetByEmail", ctx, "abc@gmail.com").Return(user, nil)
		userRepo.On("Update", ctx, user).Return(test.ErrTest)
		app.Cfg.JwtSecret = "not so secret"
		authJWT := jwt.NewJWT(app.Cfg)
		authHandler := handler.NewAuth(&app, authJWT, userRepo)
		authHandler.Login(res, req)

		assert.Equal(t, http.StatusInternalServerError, res.Code)
		userRepo.AssertExpectations(t)
	})

	t.Run("if login succeeds, return user data with tokens", func(t *testing.T) {
		res := httptest.NewRecorder()
		var body = []byte(`{"email": "abc@gmail.com", "password":"12345678"}`)
		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		require.NoError(t, err)

		user := &model.User{
			ID:       1,
			Roles:    []string{model.RoleUser},
			Password: "$2a$10$/O5r9A49M0ewJjsXvoh7dOzF.OdazGXYi/qTf/b3.u6zOk0JQv4U.",
			Active:   true,
		}
		userRepo := &mocks.UserRepo{}
		userRepo.On("GetByEmail", ctx, "abc@gmail.com").Return(user, nil)
		userRepo.On("Update", ctx, user).Return(nil)
		app.Cfg.JwtSecret = "not so secret"
		authJWT := jwt.NewJWT(app.Cfg)
		authHandler := handler.NewAuth(&app, authJWT, userRepo)
		authHandler.Login(res, req)

		assert.Equal(t, http.StatusOK, res.Code)
		items := test.Body2Items(t, res.Body)

		assert.NoError(t, err)
		assert.Equal(t, float64(1), items[0]["id"])
		assert.NotEmpty(t, items[0]["access_token"])
		assert.NotEmpty(t, items[0]["refresh_token"])

		userRepo.AssertExpectations(t)
	})
}
