package server

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"

	"github.com/0xTatsu/mvtn-api/internal/config"
	"github.com/0xTatsu/mvtn-api/internal/validate"
)

type App struct {
	cfg *config.Configuration
	// db         *sqlx.DB
	router     *chi.Mux
	httpServer *http.Server
	validator  *validator.Validate
}

func NewApp() *App {
	return &App{}
}

func (a *App) Init() {
	a.cfg, _ = config.New()
	a.validator = validate.New()
}

func (s *Server) newRouter() {
	s.router = chi.NewRouter()
}

func (s *Server) setGlobalMiddleware() {
	s.router.Use(middleware.Json)
	s.router.Use(middleware.Cors)
	if s.cfg.Api.RequestLog {
		s.router.Use(chiMiddleware.Logger)
	}
	s.router.Use(chiMiddleware.Recoverer)
}

func (s *Server) Migrate() {
	if s.cfg.DockerTest.Driver == "postgres" {
		driver, err := postgres.WithInstance(s.DB().DB, &postgres.Config{})
		if err != nil {
			log.Fatalf("error instantiating database: %v", err)
		}
		m, err := migrate.NewWithDatabaseInstance(
			databaseMigrationPath, s.cfg.DockerTest.Driver, driver,
		)
		if err != nil {
			log.Fatalf("error connecting to database: %v", err)
		}
		log.Println("migrating...")
		err = m.Up()
		if err != nil {
			if err != migrate.ErrNoChange {
				log.Panicf("error migrating: %v", err)
			}
		}

		log.Println("done migration.")
	}
}

func (a *App) Run() error {
	a.httpServer = &http.Server{
		Addr:    ":" + a.cfg.Server.Port,
		Handler: a.router,
	}

	return a.httpServer.ListenAndServe()
}
