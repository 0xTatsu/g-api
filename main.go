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

	"github.com/0xTatsu/g-api/handler"
	"github.com/0xTatsu/g-api/jwt"

	"github.com/0xTatsu/g-api/config"
	appValidator "github.com/0xTatsu/g-api/handler/validator"
	"github.com/0xTatsu/g-api/model"
	"github.com/0xTatsu/g-api/repo"
)

func main() {
	_, undoReplaceGlobalLog := initLogger()
	defer undoReplaceGlobalLog()

	envCfg, err := config.New()
	if err != nil {
		log.Fatal("cannot load config:", err)
	}

	app := model.App{
		Cfg:       envCfg,
		Validator: appValidator.New(validator.New()),
	}

	db := initDB(envCfg.DbUrl)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Heartbeat("/ping"))
	r.Use(middleware.Timeout(time.Second * time.Duration(app.Cfg.ServerTimeout)))
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
		port = envCfg.ServerPort
	}

	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("cannot start server: %s", err)
	}
}

func initLogger() (*zap.Logger, func()) {
	logger, errZapLog := zap.NewDevelopment()
	if errZapLog != nil {
		log.Fatalf("cannot init ZAP log: %s", errZapLog)
	}

	undoReplaceGlobalLog := zap.ReplaceGlobals(logger)

	return logger, undoReplaceGlobalLog
}

func initDB(dbURL string) *pg.DB {
	opt, err := pg.ParseURL(dbURL)
	if err != nil {
		log.Fatalf("cannot connect db: %s", err)
	}

	return pg.Connect(opt)
}
