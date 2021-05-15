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
	"go.uber.org/zap"

	"github.com/0xTatsu/mvtn-api/auth"
	"github.com/0xTatsu/mvtn-api/auth/jwt"
	"github.com/0xTatsu/mvtn-api/config"
	"github.com/0xTatsu/mvtn-api/validate"
)

func main() {
	// init logger
	logger, errZapLog := zap.NewDevelopment()
	if errZapLog != nil {
		log.Fatalf("failed to init ZAP log: %s", errZapLog)
	}

	undoReplaceGlobalLog := zap.ReplaceGlobals(logger)
	defer undoReplaceGlobalLog()

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

	authJWT := jwt.NewJWT(app.cfg)
	authAPI := auth.NewAPI(authJWT)

	// Public routes
	r.Mount("/auth", authAPI.Router(r))

	// Protected routes
	r.Group(func(r chi.Router) {
		// Seek, verify and validate JWT tokens
		r.Use(authJWT.Verifier())

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
