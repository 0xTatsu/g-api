package handler

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/0xTatsu/mvtn-api/handler/res"
	"github.com/0xTatsu/mvtn-api/jwt"
	"github.com/0xTatsu/mvtn-api/model"
	"github.com/0xTatsu/mvtn-api/repo"
)

type Auth struct {
	app         *model.App
	authJWT     *jwt.AuthJWT
	accountRepo repo.AccountRepo
}

func NewAuth(
	app *model.App,
	authJWT *jwt.AuthJWT,
	accountRepo repo.AccountRepo,
) *Auth {
	return &Auth{
		app:         app,
		authJWT:     authJWT,
		accountRepo: accountRepo,
	}
}

func (a *Auth) Router(r *chi.Mux) *chi.Mux {
	r.Post("/register", a.Register)
	r.Post("/login", a.Login)
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

func (a *Auth) Register(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Email           string `json:"email" validate:"required,email"`
		Password        string `json:"password" validate:"required,min=8"`
		ConfirmPassword string `json:"confirm_password" validate:"eqfield=Password"`
	}

	var body request
	if err := render.DecodeJSON(r.Body, &body); err != nil {
		res.WithErrorMsg(w, r, err.Error())
		return
	}

	if validationErrors := a.app.Validator.Validate(body); len(validationErrors) != 0 {
		res.WithErrors(w, r, validationErrors)

		return
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		zap.L().Error("cannot generate hash password", zap.Error(err))
		res.InternalServerError(w, r)
	}

	account := &model.Account{
		LastLogin: time.Now(),
		Email:     body.Email,
		Active:    true,
		Roles:     []string{model.RoleUser},
		Password:  string(hashPassword),
	}

	if _, err := a.accountRepo.Create(r.Context(), account); err != nil {
		zap.L().Error("cannot create account", zap.Error(err))
		res.InternalServerError(w, r)
		return
	}

	res.Created(w, r)
}

func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required,min=8"`
	}

	var body request
	if err := render.DecodeJSON(r.Body, &body); err != nil {
		res.WithErrorMsg(w, r, err.Error())
		return
	}

	if validationErrors := a.app.Validator.Validate(body); validationErrors != nil {
		res.WithErrors(w, r, validationErrors)
		return
	}

	account, err := a.accountRepo.GetByEmail(r.Context(), body.Email)
	if err != nil {
		zap.L().Error("cannot get account by email", zap.Error(err))
		res.InternalServerError(w, r)
		return
	}

	if !account.IsValidPassword(body.Password) {
		res.Unauthorized(w, r)
		return
	}

	if !account.CanLogin() {
		res.Unauthorized(w, r)
		return
	}

	refreshClaims := jwt.RefreshClaims{ID: account.ID}
	accessToken, refreshToken, err := a.authJWT.CreateTokenPair(account.Claims(), refreshClaims)
	if err != nil {
		res.InternalServerError(w, r)
		return
	}

	account.LastLogin = time.Now()
	if err := a.accountRepo.Update(r.Context(), account); err != nil {
		zap.L().Error("cannot update lastLogin", zap.Error(err))
		res.InternalServerError(w, r)
		return
	}

	account.AccessToken = accessToken
	account.RefreshToken = refreshToken

	res.WithItem(w, r, account)
}

func (a *Auth) forgetPassword(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Password        string `json:"password" validate:"required,min=8"`
		NewPassword     string `json:"new_password" validate:"required,min=8"`
		ConfirmPassword string `json:"confirm_password" validate:"eqfield=NewPassword"`
	}

	body := request{}
	if err := render.DecodeJSON(r.Body, &body); err != nil {
		res.WithErrorMsg(w, r, err.Error())
		return
	}

	if validationErrors := a.app.Validator.Validate(body); len(validationErrors) != 0 {
		res.WithErrors(w, r, validationErrors)

		return
	}

	accessClaims := jwt.ClaimsFromCtx(r.Context())
	account, err := a.accountRepo.GetByID(r.Context(), accessClaims.ID)
	if err != nil {
		zap.L().Error("cannot get account by ID", zap.Error(err))
		res.InternalServerError(w, r)

		return
	}

	if !account.IsValidPassword(body.Password) {
		res.Unauthorized(w, r)
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		zap.L().Error("cannot generate has from password", zap.Error(err))
		res.InternalServerError(w, r)
	}

	account.Password = string(hashPassword)
	if err := a.accountRepo.Update(r.Context(), account); err != nil {
		zap.L().Error("cannot update password", zap.Error(err))
		res.InternalServerError(w, r)
		return
	}

	res.NoContent(w, r)
}

func (a *Auth) logout(w http.ResponseWriter, r *http.Request) {
	c := &http.Cookie{
		Name:     a.app.Cfg.JwtHttpCookieKey,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}

	http.SetCookie(w, c)

	render.JSON(w, r, http.NoBody)
}

func (a *Auth) refreshToken(w http.ResponseWriter, r *http.Request) {
	refreshClaims := jwt.RefreshClaimsFromCtx(r.Context())

	account, err := a.accountRepo.GetByID(r.Context(), refreshClaims.ID)
	if err != nil {
		zap.L().Error("cannot get account by email", zap.Error(err))
		res.InternalServerError(w, r)
		return
	}

	if !account.CanLogin() {
		res.Unauthorized(w, r)
		return
	}

	accessToken, refreshToken, err := a.authJWT.CreateTokenPair(account.Claims(), refreshClaims)
	if err != nil {
		res.InternalServerError(w, r)
		return
	}

	account.LastLogin = time.Now()
	if err := a.accountRepo.Update(r.Context(), account); err != nil {
		zap.L().Error("cannot update lastLogin", zap.Error(err))
		res.InternalServerError(w, r)
		return
	}

	account.AccessToken = accessToken
	account.RefreshToken = refreshToken

	res.WithItem(w, r, account)
}
