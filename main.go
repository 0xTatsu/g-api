package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/go-pg/pg/v10"
	"github.com/go-playground/validator/v10"

	"github.com/0xTatsu/mvtn-api/internal/config"
	"github.com/0xTatsu/mvtn-api/internal/validate"
)

var tokenAuth *jwtauth.JWTAuth

func init() {
	tokenAuth = jwtauth.New("HS256", []byte("secret"), nil)

	// For debugging/example purposes, we generate and print
	// a sample jwt token with claims `user_id:123` here:
	_, tokenString, _ := tokenAuth.Encode(map[string]interface{}{"user_id": 123})
	fmt.Printf("DEBUG: a sample jwt is %s\n\n", tokenString)
}

func main() {
	type App struct {
		cfg       *config.Configuration
		validator *validator.Validate
		db        *pg.DB
	}

	var app App

	app.cfg = config.New()
	app.validator = validate.New()
	app.db = pg.Connect(&pg.Options{
		Addr:     app.cfg.DB.Addr,
		User:     app.cfg.DB.User,
		Password: app.cfg.DB.Pass,
	})

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Heartbeat("/ping"))
	r.Use(middleware.Timeout(time.Second * time.Duration(app.cfg.Server.Timeout)))
	r.Use(render.SetContentType(render.ContentTypeJSON))

	// Public routes
	r.Group(func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("welcome anonymous"))
		})
	})

	// Protected routes
	r.Group(func(r chi.Router) {
		// Seek, verify and validate JWT tokens
		r.Use(jwtauth.Verifier(tokenAuth))

		// Handle valid / invalid tokens. In this example, we use
		// the provided authenticator middleware, but you can write your
		// own very easily, look at the Authenticator method in jwtauth.go
		// and tweak it, its not scary.
		r.Use(jwtauth.Authenticator)

		r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
			_, claims, _ := jwtauth.FromContext(r.Context())
			w.Write([]byte(fmt.Sprintf("protected area. hi %v", claims["user_id"])))
		})
	})

	if err := http.ListenAndServe(app.cfg.Server.Address, r); err != nil {
		log.Fatalf("cannot start server: %s", err)
	}
}
