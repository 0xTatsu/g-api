package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/go-pg/pg/v10"
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"

	"github.com/0xTatsu/mvtn-api/handler"
	"github.com/0xTatsu/mvtn-api/jwt"

	"github.com/0xTatsu/mvtn-api/config"
	appValidator "github.com/0xTatsu/mvtn-api/handler/validator"
	"github.com/0xTatsu/mvtn-api/model"
	"github.com/0xTatsu/mvtn-api/repo"
)

func main() {
	// init logger
	logger, errZapLog := zap.NewDevelopment()
	if errZapLog != nil {
		log.Fatalf("failed to init ZAP log: %s", errZapLog)
	}

	undoReplaceGlobalLog := zap.ReplaceGlobals(logger)
	defer undoReplaceGlobalLog()

	envCfg := config.New()
	app := model.App{
		Cfg:       envCfg,
		Validator: appValidator.New(validator.New()),
	}

	db := pg.Connect(&pg.Options{Addr: app.Cfg.DB.Addr, Database: app.Cfg.DB.Name, User: app.Cfg.DB.User, Password: app.Cfg.DB.Pass})

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Heartbeat("/ping"))
	r.Use(middleware.Timeout(time.Second * time.Duration(app.Cfg.Server.Timeout)))
	r.Use(render.SetContentType(render.ContentTypeJSON))

	authJWT := jwt.NewJWT(app.Cfg)
	accountRepo := repo.NewAccount(db)
	authAPI := handler.NewAuth(&app, authJWT, accountRepo)

	// Public routes
	r.Mount("/auth", authAPI.Router(r))

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(authJWT.Verifier())
		r.Use(jwt.Authenticator)

		r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
			_, claims, _ := jwtauth.FromContext(r.Context())
			fmt.Println(claims)
			render.JSON(w, r, http.NoBody)
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = envCfg.Server.Port
	}

	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("cannot start server: %s", err)
	}
}
