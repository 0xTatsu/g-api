package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/0xTatsu/g-api/config"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/0xTatsu/g-api/handler/validator"
	"github.com/0xTatsu/g-api/jwt"
	"github.com/0xTatsu/g-api/model"
	"github.com/0xTatsu/g-api/repo"
	"github.com/0xTatsu/g-api/res"
)

type Auth struct {
	authJWT   JWT
	userRepo  UserRepo
	cfg       *config.Env
	validator *validator.Validator
}

func NewAuth(
	authJWT JWT,
	userRepo UserRepo,
	cfg *config.Env,
	validator *validator.Validator,
) *Auth {
	return &Auth{
		cfg:       cfg,
		authJWT:   authJWT,
		userRepo:  userRepo,
		validator: validator,
	}
}

func (h *Auth) Router(r *chi.Mux) *chi.Mux {
	r.Method(http.MethodPost, "/register", Handler{h.Register})
	r.Method(http.MethodPost, "/login", Handler{h.Login})

	r.Group(func(r chi.Router) {
		r.Use(h.authJWT.Verifier())
		r.Use(jwt.Authenticator)
		r.Method(http.MethodPut, "/change-password", Handler{h.ChangePassword})
		r.Method(http.MethodPost, "/logout", Handler{h.Logout})
	})

	// r.Group(func(r chi.Router) {
	// 	r.Use(h.authJWT.Verifier())
	// 	r.Use(jwt.AuthenticateRefreshJWT)
	// 	r.Method(http.MethodPost, "/token", Handler{h.refreshToken})
	// })

	return r
}

func (h *Auth) Register(w http.ResponseWriter, r *http.Request) (interface{}, interface{}) {
	type request struct {
		Email           string `json:"email" validate:"required,email"`
		Password        string `json:"password" validate:"required,min=8"`
		ConfirmPassword string `json:"confirmPassword" validate:"eqfield=Password"`
	}

	var body request
	if err := render.DecodeJSON(r.Body, &body); err != nil {
		return nil, err
	}

	if validateErrs := h.validator.Validate(body); validateErrs.Errors != nil {
		return nil, validateErrs
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		zap.L().Error("cannot generate hash password", zap.Error(err))
		return nil, http.StatusInternalServerError
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
		return nil, res.Error{Code: res.CodeDuplicatedKey, Msg: repo.ErrDuplicateKey.Error()}
	}

	if createError != nil {
		zap.L().Error("cannot create user", zap.Error(err))
		return nil, res.Error{HTTPCode: http.StatusInternalServerError}
	}

	return http.StatusCreated, nil
}

func (h *Auth) Login(w http.ResponseWriter, r *http.Request) (interface{}, interface{}) {
	type request struct {
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required,min=8"`
	}

	var body request
	if err := render.DecodeJSON(r.Body, &body); err != nil {
		return nil, err
	}

	if validateErrs := h.validator.Validate(body); validateErrs.Errors != nil {
		return nil, validateErrs
	}

	user, err := h.userRepo.GetByEmail(r.Context(), body.Email)
	if err != nil {
		zap.L().Error("cannot get user by email", zap.Error(err))
		return nil, res.Error{HTTPCode: http.StatusInternalServerError}
	}

	if !user.IsValidPassword(body.Password) {
		return nil, res.Error{HTTPCode: http.StatusUnauthorized}
	}

	if !user.CanLogin() {
		return nil, res.Error{HTTPCode: http.StatusUnauthorized}
	}

	accessClaims := user.AccessClaims()
	refreshClaims := jwt.RefreshClaims{ID: user.ID}
	accessToken, _, err := h.authJWT.CreateTokenPair(accessClaims, refreshClaims)
	if err != nil {
		return nil, res.Error{HTTPCode: http.StatusInternalServerError}
	}

	user.LastLogin = time.Now()
	if err := h.userRepo.Update(r.Context(), user); err != nil {
		zap.L().Error("cannot update lastLogin", zap.Error(err))
		return nil, res.Error{HTTPCode: http.StatusInternalServerError}
	}

	user.AccessToken = accessToken
	// user.RefreshToken = refreshToken

	return user, nil
}

func (h *Auth) ChangePassword(w http.ResponseWriter, r *http.Request) (interface{}, interface{}) {
	type request struct {
		Password        string `json:"password" validate:"required,min=8"`
		NewPassword     string `json:"newPassword" validate:"required,min=8"`
		ConfirmPassword string `json:"confirmPassword" validate:"eqfield=NewPassword"`
	}

	body := request{}
	if err := render.DecodeJSON(r.Body, &body); err != nil {
		return nil, err
	}

	if validateErrs := h.validator.Validate(body); validateErrs.Errors != nil {
		return nil, validateErrs
	}

	accessClaims := AccessClaimsFromCtx(r.Context())
	user, err := h.userRepo.GetByID(r.Context(), accessClaims.ID)
	if err != nil {
		zap.L().Error("cannot get user by ID", zap.Error(err))
		return nil, res.Error{HTTPCode: http.StatusInternalServerError}
	}

	if !user.IsValidPassword(body.Password) {
		err := res.Errors{{Code: res.CodeIncorrectOldPass, Field: "password", Msg: "old password is incorrect"}}
		return nil, res.Error{Errors: &err}
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		zap.L().Error("cannot generate has from password", zap.Error(err))
		return nil, res.Error{HTTPCode: http.StatusInternalServerError}
	}

	user.Password = string(hashPassword)
	if err := h.userRepo.Update(r.Context(), user); err != nil {
		zap.L().Error("cannot update password", zap.Error(err))
		return nil, res.Error{HTTPCode: http.StatusInternalServerError}
	}

	// TODO: Logout

	return http.StatusNoContent, nil
}

func (h *Auth) Logout(w http.ResponseWriter, r *http.Request) (interface{}, interface{}) {
	c := &http.Cookie{
		Name:     h.cfg.JwtHTTPCookieKey,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}

	http.SetCookie(w, c)

	return http.StatusOK, nil
}

// func (h *Auth) refreshToken(w http.ResponseWriter, r *http.Request) (interface{}, interface{}) {
// 	refreshClaims := RefreshClaimsFromCtx(r.Context())
//
// 	user, err := h.userRepo.GetByID(r.Context(), refreshClaims.ID)
// 	if err != nil {
// 		zap.L().Error("cannot get user by email", zap.Error(err))
// 		return nil, res.Error{HTTPCode: http.StatusInternalServerError}
// 	}
//
// 	if !user.CanLogin() {
// 		return nil, res.Error{HTTPCode: http.StatusUnauthorized}
// 	}
//
// 	accessToken, refreshToken, err := h.authJWT.CreateTokenPair(user.AccessClaims(), refreshClaims)
// 	if err != nil {
// 		return nil, res.Error{HTTPCode: http.StatusInternalServerError}
// 	}
//
// 	user.LastLogin = time.Now()
// 	if err := h.userRepo.Update(r.Context(), user); err != nil {
// 		zap.L().Error("cannot update lastLogin", zap.Error(err))
// 		return nil, res.Error{HTTPCode: http.StatusInternalServerError}
// 	}
//
// 	user.AccessToken = accessToken
// 	user.RefreshToken = refreshToken
//
// 	return user, nil
// }
