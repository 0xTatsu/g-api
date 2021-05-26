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
		switch err.(type) {
		case res.Error:
			val := err.(res.Error)
			httpStatusCode := http.StatusBadRequest
			if val.HttpCode != 0 {
				httpStatusCode = val.HttpCode
			}

			if val.Code == "" && val.Msg == "" && val.Errors == nil {
				res.WithNoContent(w, r, httpStatusCode)
				return
			}

			res.WithError(w, r, httpStatusCode, val)
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
		switch data.(type) {
		case int:
			res.WithNoContent(w, r, data.(int))
		default:
			res.WithData(w, r, data)
			return
		}
	}
}

type Validator interface {
	Validate(input interface{}) res.Error
}

//go:generate mockery --name JWT --case snake
type JWT interface {
	CreateAccessToken(c jwt.AccessClaims) (string, error)
	CreateRefreshToken(c jwt.RefreshClaims) (string, error)
	CreateTokenPair(accessClaims jwt.AccessClaims, refreshClaims jwt.RefreshClaims) (string, string, error)
	Verifier() func(http.Handler) http.Handler
	ClaimsFromCtx(ctx context.Context) jwt.AccessClaims
	RefreshClaimsFromCtx(ctx context.Context) jwt.RefreshClaims
}

//go:generate mockery --name UserRepo --case snake
type UserRepo interface {
	GetByID(ctx context.Context, id uint) (*model.User, error)
	GetByEmail(ctx context.Context, email string) (*model.User, error)
	Update(ctx context.Context, user *model.User) error
	Create(ctx context.Context, user *model.User) (*model.User, error)
}
