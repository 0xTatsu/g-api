package auth

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"go.uber.org/zap"

	"github.com/0xTatsu/mvtn-api/auth/jwt"
	"github.com/0xTatsu/mvtn-api/model"
	"github.com/0xTatsu/mvtn-api/repo"
	"github.com/0xTatsu/mvtn-api/response"
	"github.com/0xTatsu/mvtn-api/validate"
)

var (
	ErrInvalidLogin  = errors.New("invalid email address")
	ErrUnknownLogin  = errors.New("email not registered")
	ErrLoginDisabled = errors.New("login for account disabled")
	ErrLoginToken    = errors.New("invalid or expired login token")
)

type API struct {
	app         *model.App
	authJWT     *jwt.AuthJWT
	accountRepo repo.AccountRepo
}

func NewAPI(
	app *model.App,
	authJWT *jwt.AuthJWT,
	accountRepo repo.AccountRepo,
) *API {
	return &API{
		app:         app,
		authJWT:     authJWT,
		accountRepo: accountRepo,
	}
}

func (a *API) Router(r *chi.Mux) *chi.Mux {
	r.Post("/register", a.register)
	r.Post("/login", a.login)
	r.Post("/forget-password", a.forgetPassword)

	r.Group(func(r chi.Router) {
		r.Use(a.authJWT.Verifier())
		r.Use(jwt.Authenticator)
		r.Post("/logout", a.logout)
	})

	r.Group(func(r chi.Router) {
		r.Use(a.authJWT.Verifier())
		r.Use(jwt.AuthenticateRefreshJWT)
		r.Post("/token", a.refreshToken)
	})

	return r
}

type registerRequest struct {
	Email           string `json:"email" validate:"required,email"`
	Password        string `json:"password" validate:"required,gt=8"`
	ConfirmPassword string `json:"confirm_password" validate:"eqfield=password"`
}

func (a *API) register(w http.ResponseWriter, r *http.Request) {
	var body registerRequest
	if err := render.DecodeJSON(r.Body, body); err != nil {
		response.Error(http.StatusBadRequest, err)
		return
	}

	if err := validate.Validate(a.app.Validator, body); err != nil {
		response.Error(http.StatusBadRequest, errors.New(err[0]))
		return
	}

	account := &model.Account{
		LastLogin: time.Now(),
		Email:     body.Email,
		Active:    true,
		Roles:     []string{model.RoleUser},
	}

	if _, err := a.accountRepo.Create(r.Context(), account); err != nil {
		zap.L().Error("cannot update lastLogin", zap.Error(err))
		response.Error(http.StatusInternalServerError, nil)
		return
	}

	render.JSON(w, r, http.StatusCreated)
}

type loginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,gt=8"`
}

type loginResponse struct {
	Account      *model.Account `json:"account"`
	AccessToken  string         `json:"access_token"`
	RefreshToken string         `json:"refresh_token"`
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var body loginRequest
	if err := render.DecodeJSON(r.Body, body); err != nil {
		response.Error(http.StatusBadRequest, err)
		return
	}

	if err := validate.Validate(a.app.Validator, body); err != nil {
		response.Error(http.StatusBadRequest, errors.New(err[0]))
		return
	}

	account, err := a.accountRepo.GetByEmail(r.Context(), body.Email)
	if err != nil {
		zap.L().Error("cannot get account by email", zap.Error(err))
		response.Error(http.StatusInternalServerError, nil)
		return
	}

	if !account.CanLogin() {
		response.Error(http.StatusUnauthorized, ErrLoginDisabled)
		return
	}

	refreshClaims := jwt.RefreshClaims{ID: account.ID}
	accessToken, refreshToken, err := a.authJWT.CreateTokenPair(account.Claims(), refreshClaims)
	if err != nil {
		response.Error(http.StatusInternalServerError, nil)
		return
	}

	account.LastLogin = time.Now()
	if err := a.accountRepo.Update(r.Context(), account); err != nil {
		zap.L().Error("cannot update lastLogin", zap.Error(err))
		response.Error(http.StatusInternalServerError, nil)
		return
	}

	render.JSON(w, r, &loginResponse{
		Account:      account,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

func (a *API) forgetPassword(w http.ResponseWriter, r *http.Request) {

}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	c := &http.Cookie{
		Name:     a.app.Cfg.JWT.HttpCookieKey,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}

	http.SetCookie(w, c)

	render.JSON(w, r, http.NoBody)
}

func (a *API) refreshToken(w http.ResponseWriter, r *http.Request) {
	refreshClaims := jwt.RefreshClaimsFromCtx(r.Context())

	account, err := a.accountRepo.GetByID(r.Context(), refreshClaims.ID)
	if err != nil {
		zap.L().Error("cannot get account by email", zap.Error(err))
		response.Error(http.StatusInternalServerError, nil)
		return
	}

	if !account.CanLogin() {
		response.Error(http.StatusUnauthorized, ErrLoginDisabled)
		return
	}

	accessToken, refreshToken, err := a.authJWT.CreateTokenPair(account.Claims(), refreshClaims)
	if err != nil {
		response.Error(http.StatusInternalServerError, nil)
		return
	}

	account.LastLogin = time.Now()
	if err := a.accountRepo.Update(r.Context(), account); err != nil {
		zap.L().Error("cannot update lastLogin", zap.Error(err))
		response.Error(http.StatusInternalServerError, nil)
		return
	}

	render.JSON(w, r, &loginResponse{
		Account:      account,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}
