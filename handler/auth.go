package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/0xTatsu/g-api/handler/res"
	"github.com/0xTatsu/g-api/jwt"
	"github.com/0xTatsu/g-api/model"
	"github.com/0xTatsu/g-api/repo"
)

type Auth struct {
	app      *model.App
	authJWT  jwt.JWT
	userRepo repo.UserRepo
}

func NewAuth(
	app *model.App,
	authJWT jwt.JWT,
	userRepo repo.UserRepo,
) *Auth {
	return &Auth{
		app:      app,
		authJWT:  authJWT,
		userRepo: userRepo,
	}
}

func (h *Auth) Router(r *chi.Mux) *chi.Mux {
	r.Post("/register", h.Register)
	r.Post("/login", h.Login)

	r.Group(func(r chi.Router) {
		r.Use(h.authJWT.Verifier())
		r.Use(jwt.Authenticator)
		r.Put("/change-password", h.ChangePassword)
		r.Post("/logout", h.logout)
	})

	r.Group(func(r chi.Router) {
		r.Use(h.authJWT.Verifier())
		r.Use(jwt.AuthenticateRefreshJWT)
		r.Post("/token", h.refreshToken)
	})

	return r
}

func (h *Auth) Register(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Email           string `json:"email" validate:"required,email"`
		Password        string `json:"password" validate:"required,min=8"`
		ConfirmPassword string `json:"confirm_password" validate:"eqfield=Password"`
	}

	var body request
	if err := render.DecodeJSON(r.Body, &body); err != nil {
		res.DecodeError(w, r, err)
		return
	}

	if validationErrors := h.app.Validator.Validate(body); len(validationErrors) != 0 {
		res.ValidateErrors(w, r, validationErrors)
		return
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		zap.L().Error("cannot generate hash password", zap.Error(err))
		res.InternalServerError(w, r)
	}

	user := &model.User{
		LastLogin: time.Now(),
		Email:     body.Email,
		Active:    true,
		Roles:     []string{model.RoleUser},
		Password:  string(hashPassword),
	}

	_, createError := h.userRepo.Create(r.Context(), user)
	if errors.Is(createError, repo.ErrDuplicateKey) {
		res.WithError(w, r, res.Error{Code: res.DuplicatedKey, Msg: repo.ErrDuplicateKey.Error()})
		return
	}

	if createError != nil {
		zap.L().Error("cannot create user", zap.Error(err))
		res.InternalServerError(w, r)
		return
	}

	res.Created(w, r)
}

func (h *Auth) Login(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required,min=8"`
	}

	var body request
	if err := render.DecodeJSON(r.Body, &body); err != nil {
		res.DecodeError(w, r, err)
		return
	}

	if validationErrors := h.app.Validator.Validate(body); validationErrors != nil {
		res.ValidateErrors(w, r, validationErrors)
		return
	}

	user, err := h.userRepo.GetByEmail(r.Context(), body.Email)
	if err != nil {
		zap.L().Error("cannot get user by email", zap.Error(err))
		res.InternalServerError(w, r)
		// TODO: distinguish record not found
		return
	}

	if !user.IsValidPassword(body.Password) {
		res.Unauthorized(w, r)
		return
	}

	if !user.CanLogin() {
		res.Unauthorized(w, r)
		return
	}

	refreshClaims := jwt.RefreshClaims{ID: user.ID}
	accessToken, refreshToken, err := h.authJWT.CreateTokenPair(user.Claims(), refreshClaims)
	if err != nil {
		res.InternalServerError(w, r)
		return
	}

	user.LastLogin = time.Now()
	if err := h.userRepo.Update(r.Context(), user); err != nil {
		zap.L().Error("cannot update lastLogin", zap.Error(err))
		res.InternalServerError(w, r)
		return
	}

	user.AccessToken = accessToken
	user.RefreshToken = refreshToken

	res.WithItem(w, r, user)
}

func (h *Auth) ChangePassword(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Password        string `json:"password" validate:"required,min=8"`
		NewPassword     string `json:"new_password" validate:"required,min=8"`
		ConfirmPassword string `json:"confirm_password" validate:"eqfield=NewPassword"`
	}

	body := request{}
	if err := render.DecodeJSON(r.Body, &body); err != nil {
		res.DecodeError(w, r, err)
		return
	}

	if validationErrors := h.app.Validator.Validate(body); len(validationErrors) != 0 {
		res.WithErrors(w, r, validationErrors)
		return
	}

	accessClaims := h.authJWT.ClaimsFromCtx(r.Context())
	user, err := h.userRepo.GetByID(r.Context(), accessClaims.ID)
	if err != nil {
		zap.L().Error("cannot get user by ID", zap.Error(err))
		res.InternalServerError(w, r)
		return
	}

	if !user.IsValidPassword(body.Password) {
		res.WithError(w, r, res.Error{
			Code:  res.IncorrectOldPass,
			Field: "password",
			Msg:   "old password is incorrect",
		})
		return
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		zap.L().Error("cannot generate has from password", zap.Error(err))
		res.InternalServerError(w, r)
	}

	user.Password = string(hashPassword)
	if err := h.userRepo.Update(r.Context(), user); err != nil {
		zap.L().Error("cannot update password", zap.Error(err))
		res.InternalServerError(w, r)
		return
	}

	res.Updated(w, r)
}

func (h *Auth) logout(w http.ResponseWriter, r *http.Request) {
	c := &http.Cookie{
		Name:     h.app.Cfg.JwtHttpCookieKey,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}

	http.SetCookie(w, c)

	res.NoData(w, r, http.StatusOK)
}

func (h *Auth) refreshToken(w http.ResponseWriter, r *http.Request) {
	refreshClaims := h.authJWT.RefreshClaimsFromCtx(r.Context())

	user, err := h.userRepo.GetByID(r.Context(), refreshClaims.ID)
	if err != nil {
		zap.L().Error("cannot get user by email", zap.Error(err))
		res.InternalServerError(w, r)
		return
	}

	if !user.CanLogin() {
		res.Unauthorized(w, r)
		return
	}

	accessToken, refreshToken, err := h.authJWT.CreateTokenPair(user.Claims(), refreshClaims)
	if err != nil {
		res.InternalServerError(w, r)
		return
	}

	user.LastLogin = time.Now()
	if err := h.userRepo.Update(r.Context(), user); err != nil {
		zap.L().Error("cannot update lastLogin", zap.Error(err))
		res.InternalServerError(w, r)
		return
	}

	user.AccessToken = accessToken
	user.RefreshToken = refreshToken

	res.WithItem(w, r, user)
}
