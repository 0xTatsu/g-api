package handler

import (
	"context"
	"net/http"

	"github.com/0xTatsu/g-api/config"
	"github.com/0xTatsu/g-api/jwt"
	"github.com/0xTatsu/g-api/model"
	"github.com/0xTatsu/g-api/res"
)

// Env An application-wide configuration.
type Env struct {
	Cfg       config.Env
	Validator Validator
}

type Handler struct {
	H func(w http.ResponseWriter, r *http.Request) (interface{}, error)
}

// ServeHTTP allows our Handler type to satisfy http.Handler.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data, err := h.H(w, r)
	if err != nil {
		switch err := err.(type) {
		case res.Error:
			httpStatusCode := http.StatusBadRequest
			if err.HttpCode != 0 {
				httpStatusCode = err.HttpCode
			}

			if err.Code == "" && err.Msg == "" && err.Errors == nil {
				res.WithNoContent(w, r, httpStatusCode)
				return
			}

			res.WithError(w, r, httpStatusCode, err)
			return

		case error:
			res.WithErrMsg(w, r, http.StatusBadRequest, err.(error).Error())
			return

		default:
			// Any error types we don't specifically look out for default
			// to serving a HTTP 500
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}

	if data != nil {
		switch data := data.(type) {
		case int:
			res.WithNoContent(w, r, data)
		default:
			res.WithData(w, r, data)
			return
		}
	}
}

type Validator interface {
	Validate(input interface{}) res.Error
}

// AccessClaimsFromCtx retrieves the parsed AccessClaims from request context.
func AccessClaimsFromCtx(ctx context.Context) jwt.AccessClaims {
	return ctx.Value(jwt.AccessClaimCtxKey).(jwt.AccessClaims)
}

// RefreshClaimsFromCtx retrieves the parsed refresh token from context.
func RefreshClaimsFromCtx(ctx context.Context) jwt.RefreshClaims {
	return ctx.Value(jwt.RefreshClaimCtxKey).(jwt.RefreshClaims)
}

//go:generate mockery --name JWT --case snake
type JWT interface {
	CreateAccessToken(c jwt.AccessClaims) (string, error)
	CreateRefreshToken(c jwt.RefreshClaims) (string, error)
	CreateTokenPair(accessClaims jwt.AccessClaims, refreshClaims jwt.RefreshClaims) (string, string, error)
	Verifier() func(http.Handler) http.Handler
}

//go:generate mockery --name UserRepo --case snake
type UserRepo interface {
	GetByID(ctx context.Context, id uint) (*model.User, error)
	GetByEmail(ctx context.Context, email string) (*model.User, error)
	Update(ctx context.Context, user *model.User) error
	Create(ctx context.Context, user *model.User) (*model.User, error)
}
