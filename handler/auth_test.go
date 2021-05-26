package handler_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0xTatsu/g-api/config"
	"github.com/0xTatsu/g-api/handler"
	"github.com/0xTatsu/g-api/handler/mocks"
	appValidator "github.com/0xTatsu/g-api/handler/validator"
	"github.com/0xTatsu/g-api/jwt"
	"github.com/0xTatsu/g-api/model"
	"github.com/0xTatsu/g-api/res"
	"github.com/0xTatsu/g-api/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/go-playground/validator/v10"
)

var app = handler.Env{
	Cfg: config.Env{
		JwtSecret:              "",
		JwtHttpCookieKey:       "token",
		JwtExpiryInHour:        24,
		JwtRefreshExpiryInHour: 25 * 30,
	},
	Validator: appValidator.New(validator.New()),
}

const (
	ctxAccessClaimsKey  = "ctxAccessClaimsKey"
	ctxRefreshClaimsKey = "ctxRefreshClaimsKey"
	hashedPass          = "$2a$10$/O5r9A49M0ewJjsXvoh7dOzF.OdazGXYi/qTf/b3.u6zOk0JQv4U."
)

func Test_Register(t *testing.T) {
	ctx := context.TODO()
	authJWT := jwt.NewJWT(&app.Cfg)

	t.Run("if request validation fails, return errors", func(t *testing.T) {
		body := []byte(`{}`)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))

		userRepo := &mocks.UserRepo{}
		authHandler := handler.NewAuth(app, authJWT, userRepo)
		data, err := authHandler.Register(w, r)

		assert.Nil(t, data)
		assert.Error(t, err)
		errs := err.(res.Error)
		assert.Len(t, *errs.Errors, 2)
		assert.Equal(t, errs.Code, res.CodeValidationFailed)

		userRepo.AssertNotCalled(t, "Create")
	})

	t.Run("if creating user fails, return error", func(t *testing.T) {
		body := []byte(`{"email":"abc@gmail.com", "password":"12345678", "confirm_password":"12345678"}`)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))

		userRepo := &mocks.UserRepo{}
		userRepo.On("Create", ctx, mock.Anything).Return(nil, test.ErrTest)
		authHandler := handler.NewAuth(app, authJWT, userRepo)
		data, err := authHandler.Register(w, r)
		assert.Nil(t, data)
		assert.Error(t, err)
		errs := err.(res.Error)
		assert.Nil(t, errs.Errors)
		assert.Equal(t, errs.HttpCode, http.StatusInternalServerError)

		userRepo.AssertExpectations(t)
	})

	t.Run("if creating user succeeds, status will be 201", func(t *testing.T) {
		body := []byte(`{"email":"abc@gmail.com", "password":"12345678", "confirm_password":"12345678"}`)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))

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
		authHandler := handler.NewAuth(app, authJWT, userRepo)
		data, err := authHandler.Register(w, r)

		assert.Nil(t, err)
		assert.Equal(t, data, http.StatusCreated)

		userRepo.AssertExpectations(t)
	})
}

func Test_Login(t *testing.T) {
	ctx := context.TODO()
	authJWT := jwt.NewJWT(&app.Cfg)

	t.Run("if request validation fails, return errors", func(t *testing.T) {
		var body = []byte(`{"email": "abc@", "password":""}`)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))

		userRepo := &mocks.UserRepo{}
		authHandler := handler.NewAuth(app, authJWT, userRepo)
		data, err := authHandler.Login(w, r)
		assert.Nil(t, data)
		assert.Error(t, err)
		errs := err.(res.Error)
		assert.Equal(t, errs.Code, res.CodeValidationFailed)

		userRepo.AssertNotCalled(t, "GetByEmail")
	})

	t.Run("if get user by email fails, return error", func(t *testing.T) {
		var body = []byte(`{"email": "abc@gmail.com", "password":"12345678"}`)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))

		userRepo := &mocks.UserRepo{}
		userRepo.On("GetByEmail", ctx, "abc@gmail.com").Return(nil, test.ErrTest)
		authHandler := handler.NewAuth(app, authJWT, userRepo)
		data, err := authHandler.Login(w, r)
		assert.Nil(t, data)
		assert.Error(t, err)
		errs := err.(res.Error)
		assert.Equal(t, errs.HttpCode, http.StatusInternalServerError)

		userRepo.AssertExpectations(t)
	})

	t.Run("if password is incorrect return unauthorized", func(t *testing.T) {
		var body = []byte(`{"email": "abc@gmail.com", "password":"12345678"}`)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))

		user := &model.User{Password: ""}
		userRepo := &mocks.UserRepo{}
		userRepo.On("GetByEmail", ctx, "abc@gmail.com").Return(user, nil)
		authHandler := handler.NewAuth(app, authJWT, userRepo)
		data, err := authHandler.Login(w, r)
		assert.Nil(t, data)
		assert.Error(t, err)
		assert.Equal(t, err.(res.Error).HttpCode, http.StatusUnauthorized)
		userRepo.AssertExpectations(t)
	})

	t.Run("if user is not allow to login, return unauthorized", func(t *testing.T) {
		var body = []byte(`{"email": "abc@gmail.com", "password":"12345678"}`)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))

		user := &model.User{Password: hashedPass, Active: false}
		userRepo := &mocks.UserRepo{}
		userRepo.On("GetByEmail", ctx, "abc@gmail.com").Return(user, nil)
		authHandler := handler.NewAuth(app, authJWT, userRepo)
		data, err := authHandler.Login(w, r)
		assert.Nil(t, data)
		assert.Error(t, err)
		assert.Equal(t, err.(res.Error).HttpCode, http.StatusUnauthorized)
		userRepo.AssertExpectations(t)
	})

	t.Run("if create token pair fails, return internal error", func(t *testing.T) {
		var body = []byte(`{"email": "abc@gmail.com", "password":"12345678"}`)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))

		user := &model.User{
			Password: hashedPass,
			Active:   true,
		}
		userRepo := &mocks.UserRepo{}
		userRepo.On("GetByEmail", ctx, "abc@gmail.com").Return(user, nil)
		authHandler := handler.NewAuth(app, authJWT, userRepo)
		data, err := authHandler.Login(w, r)
		assert.Nil(t, data)
		assert.Error(t, err)
		assert.Equal(t, err.(res.Error).HttpCode, http.StatusInternalServerError)

		userRepo.AssertExpectations(t)
	})

	t.Run("if update user fails, return internal error", func(t *testing.T) {
		var body = []byte(`{"email": "abc@gmail.com", "password":"12345678"}`)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))

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
		authJWT := jwt.NewJWT(&app.Cfg)
		authHandler := handler.NewAuth(app, authJWT, userRepo)
		data, err := authHandler.Login(w, r)
		assert.Nil(t, data)
		assert.Error(t, err)
		assert.Equal(t, err.(res.Error).HttpCode, http.StatusInternalServerError)

		userRepo.AssertExpectations(t)
	})

	t.Run("if login succeeds, return user data with tokens", func(t *testing.T) {
		var body = []byte(`{"email": "abc@gmail.com", "password":"12345678"}`)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))

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
		authJWT := jwt.NewJWT(&app.Cfg)
		authHandler := handler.NewAuth(app, authJWT, userRepo)
		data, err := authHandler.Login(w, r)
		assert.Nil(t, err)
		user, ok := data.(*model.User)
		if assert.True(t, ok) {
			assert.Equal(t, uint(1), user.ID)
			assert.NotEmpty(t, user.AccessToken)
			assert.NotEmpty(t, user.RefreshToken)
		}

		userRepo.AssertExpectations(t)
	})
}

func Test_ChangePassword(t *testing.T) {
	ctx := context.TODO()

	t.Run("if confirm_password doesn't match, return error", func(t *testing.T) {
		var body = []byte(`{"password": "12345678", "new_password":"12345678", "confirm_password":"123456789"}`)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))

		userRepo := &mocks.UserRepo{}
		authHandler := handler.NewAuth(app, nil, userRepo)
		data, err := authHandler.ChangePassword(w, r)
		assert.Nil(t, data)
		assert.Error(t, err)
		errs := err.(res.Error)
		assert.Equal(t, errs.Code, res.CodeValidationFailed)

		userRepo.AssertNotCalled(t, "GetByID")
	})

	t.Run("if get user by ID fails, return internal error", func(t *testing.T) {
		var body = []byte(`{"password": "12345678", "new_password":"12345678", "confirm_password":"12345678"}`)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		userID := uint(1)
		authJWT := &mocks.JWT{}
		authJWT.On("ClaimsFromCtx", ctx).Return(jwt.AccessClaims{ID: userID})
		userRepo := &mocks.UserRepo{}
		userRepo.On("GetByID", ctx, userID).Return(jwt.AccessClaims{ID: userID}).Return(nil, test.ErrTest)
		authHandler := handler.NewAuth(app, authJWT, userRepo)
		data, err := authHandler.ChangePassword(w, r)
		assert.Nil(t, data)
		assert.Equal(t, err.(res.Error).HttpCode, http.StatusInternalServerError)

		authJWT.AssertExpectations(t)
		userRepo.AssertExpectations(t)
	})

	t.Run("if old password is incorrect, return error", func(t *testing.T) {
		var body = []byte(`{"password": "12345678", "new_password":"12345678", "confirm_password":"12345678"}`)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))

		userID := uint(1)
		authJWT := &mocks.JWT{}
		authJWT.On("ClaimsFromCtx", ctx).Return(jwt.AccessClaims{ID: userID})
		userRepo := &mocks.UserRepo{}
		userRepo.On("GetByID", ctx, userID).Return(jwt.AccessClaims{ID: userID}).Return(&model.User{Password: "123"}, nil)
		authHandler := handler.NewAuth(app, authJWT, userRepo)

		data, err := authHandler.ChangePassword(w, r)
		assert.Nil(t, data)
		assert.Error(t, err)
		errs := *err.(res.Error).Errors
		assert.Equal(t, errs[0].Code, res.CodeIncorrectOldPass)

		authJWT.AssertExpectations(t)
		userRepo.AssertExpectations(t)
	})

	t.Run("if update succeeds, return user data with tokens", func(t *testing.T) {
		var body = []byte(`{"password": "12345678", "new_password":"12345678", "confirm_password":"12345678"}`)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		userID := uint(1)
		user := &model.User{ID: userID, Password: hashedPass, Roles: []string{model.RoleUser}}
		authJWT := &mocks.JWT{}
		authJWT.On("ClaimsFromCtx", ctx).Return(jwt.AccessClaims{ID: userID})
		userRepo := &mocks.UserRepo{}
		userRepo.On("GetByID", ctx, userID).Return(user, nil)
		userRepo.On("Update", ctx, user).Return(nil)
		authHandler := handler.NewAuth(app, authJWT, userRepo)

		data, err := authHandler.ChangePassword(w, r)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusNoContent, data)

		authJWT.AssertExpectations(t)
		userRepo.AssertExpectations(t)
	})
}
