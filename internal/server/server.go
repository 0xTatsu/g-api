package server

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/go-pg/pg/v10"
	"github.com/go-playground/validator/v10"

	"github.com/0xTatsu/mvtn-api/internal/config"
	"github.com/0xTatsu/mvtn-api/internal/validate"
)

type App struct {
	cfg       *config.Configuration
	validator *validator.Validate
	db        *pg.DB
	// router     *chi.Mux
	// httpServer *http.Server
}

func NewApp() *App {
	return &App{}
}

func (a *App) Init() {
	a.cfg = config.New()
	a.validator = validate.New()
	a.db = a.initDB()
	// a.router = chi.NewRouter()
}

func (a *App) initDB() *pg.DB {
	return pg.Connect(&pg.Options{
		Addr:     a.cfg.DB.Addr,
		User:     a.cfg.DB.User,
		Password: a.cfg.DB.Pass,
	})
}

func (a *App) Run() error {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Heartbeat("/ping"))
	r.Use(middleware.Timeout(time.Second * time.Duration(a.cfg.Server.Timeout)))
	r.Use(render.SetContentType(render.ContentTypeJSON))

	// r.Handle("/*", authorizeHandler())

	return http.ListenAndServe(a.cfg.Server.Address, r)
}
