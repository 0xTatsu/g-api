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
	jwtMocks "github.com/0xTatsu/g-api/jwt/mocks"
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

const hashedPass = "$2a$10$/O5r9A49M0ewJjsXvoh7dOzF.OdazGXYi/qTf/b3.u6zOk0JQv4U."

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

		user := &model.User{Password: hashedPass, Active: false}
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
			Password: hashedPass,
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
			Password: hashedPass,
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
			Password: hashedPass,
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

func Test_ChangePassword(t *testing.T) {
	ctx := context.TODO()

	t.Run("if confirm_password doesn't match, return error", func(t *testing.T) {
		res := httptest.NewRecorder()
		var body = []byte(`{"password": "12345678", "new_password":"12345678", "confirm_password":"123456789"}`)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/register", bytes.NewBuffer(body))
		require.NoError(t, err)

		userRepo := &mocks.UserRepo{}
		authHandler := handler.NewAuth(&app, nil, userRepo)
		authHandler.ChangePassword(res, req)
		assert.Equal(t, http.StatusBadRequest, res.Code)
		errs := test.Body2Errors(t, res.Body)
		assert.Len(t, errs, 1)
		assert.Equal(t, errs[0].Msg, "ConfirmPassword doesn't match NewPassword")
		userRepo.AssertNotCalled(t, "GetByID")
	})

	t.Run("if get user by ID fails, return internal server error", func(t *testing.T) {
		res := httptest.NewRecorder()
		var body = []byte(`{"password": "12345678", "new_password":"12345678", "confirm_password":"12345678"}`)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/register", bytes.NewBuffer(body))
		require.NoError(t, err)
		userID := uint(1)
		authJWT := &jwtMocks.JWT{}
		authJWT.On("ClaimsFromCtx", ctx).Return(jwt.AccessClaims{ID: userID})
		userRepo := &mocks.UserRepo{}
		userRepo.On("GetByID", ctx, userID).Return(jwt.AccessClaims{ID: userID}).Return(nil, test.ErrTest)
		authHandler := handler.NewAuth(&app, authJWT, userRepo)
		authHandler.ChangePassword(res, req)
		assert.Equal(t, http.StatusInternalServerError, res.Code)
		authJWT.AssertExpectations(t)
		userRepo.AssertExpectations(t)
	})

	t.Run("if old password is incorrect, return error", func(t *testing.T) {
		res := httptest.NewRecorder()
		var body = []byte(`{"password": "12345678", "new_password":"12345678", "confirm_password":"12345678"}`)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/register", bytes.NewBuffer(body))
		require.NoError(t, err)
		userID := uint(1)
		authJWT := &jwtMocks.JWT{}
		authJWT.On("ClaimsFromCtx", ctx).Return(jwt.AccessClaims{ID: userID})
		userRepo := &mocks.UserRepo{}
		userRepo.On("GetByID", ctx, userID).Return(jwt.AccessClaims{ID: userID}).Return(&model.User{Password: "123"}, nil)
		authHandler := handler.NewAuth(&app, authJWT, userRepo)

		authHandler.ChangePassword(res, req)
		assert.Equal(t, http.StatusBadRequest, res.Code)
		errs := test.Body2Errors(t, res.Body)
		assert.Equal(t, errs[0].Code, "INCORRECT_OLD_PASSWORD")

		authJWT.AssertExpectations(t)
		userRepo.AssertExpectations(t)
	})

	t.Run("if update succeeds, return user data with tokens", func(t *testing.T) {
		res := httptest.NewRecorder()
		var body = []byte(`{"password": "12345678", "new_password":"12345678", "confirm_password":"12345678"}`)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/register", bytes.NewBuffer(body))
		require.NoError(t, err)
		userID := uint(1)
		user := &model.User{ID: userID, Password: hashedPass, Roles: []string{model.RoleUser}}
		authJWT := &jwtMocks.JWT{}
		authJWT.On("ClaimsFromCtx", ctx).Return(jwt.AccessClaims{ID: userID})
		userRepo := &mocks.UserRepo{}
		userRepo.On("GetByID", ctx, userID).Return(user, nil)
		userRepo.On("Update", ctx, user).Return(nil)
		authHandler := handler.NewAuth(&app, authJWT, userRepo)

		authHandler.ChangePassword(res, req)
		assert.Equal(t, http.StatusNoContent, res.Code)

		authJWT.AssertExpectations(t)
		userRepo.AssertExpectations(t)
	})
}
