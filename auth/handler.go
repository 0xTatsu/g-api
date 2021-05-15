package auth

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/0xTatsu/mvtn-api/auth/jwt"
)

type API struct {
	authJWT *jwt.AuthJWT
}

func NewAPI(authJWT *jwt.AuthJWT) *API {
	return &API{authJWT: authJWT}
}

func (a *API) Router(r *chi.Mux) *chi.Mux {
	r.Post("/register", a.Register)
	r.Post("/login", a.Login)
	r.Post("/forget-password", a.ForgetPassword)

	r.Group(func(r chi.Router) {
		r.Use(a.authJWT.Verifier())
		r.Use(jwt.Authenticator)
		r.Post("/logout", a.Logout)
	})

	r.Group(func(r chi.Router) {
		r.Use(a.authJWT.Verifier())
		r.Use(jwt.AuthenticateRefreshJWT)
		r.Post("/token", a.Token)
		r.Post("/refresh", a.Refresh)
	})

	return r
}

func (a *API) Register(w http.ResponseWriter, r *http.Request) {

}

func (a *API) Login(w http.ResponseWriter, r *http.Request) {

}

func (a *API) ForgetPassword(w http.ResponseWriter, r *http.Request) {

}

func (a *API) Logout(w http.ResponseWriter, r *http.Request) {

}

func (a *API) Token(w http.ResponseWriter, r *http.Request) {

}

func (a *API) Refresh(w http.ResponseWriter, r *http.Request) {

}
