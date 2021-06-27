package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/0xTatsu/g-api/config"
	"github.com/0xTatsu/g-api/handler"
	appValidator "github.com/0xTatsu/g-api/handler/validator"
	"github.com/0xTatsu/g-api/jwt"
	"github.com/0xTatsu/g-api/model"
	"github.com/0xTatsu/g-api/repo"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Server struct {
	router    *chi.Mux
	cfg       *config.Configs
	db        *gorm.DB
	log       *zap.Logger
	validator *validator.Validate
}

func NewServer() *Server {
	return &Server{
		router:    chi.NewRouter(),
		validator: validator.New(),
	}
}

func (s *Server) Start() error {
	var err error

	if s.cfg, err = config.New(); err != nil {
		return fmt.Errorf("cannot init config: %w", err)
	}

	if s.db, err = s.initDB(s.cfg.DBURL); err != nil {
		return err
	}

	if s.log, err = s.initLogger(); err != nil {
		return err
	}
	defer zap.ReplaceGlobals(s.log)

	s.globalMiddleware()
	s.routes()

	return http.ListenAndServe(":"+s.cfg.ServerPort, s.router)
}

func (s *Server) initDB(dns string) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(dns), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("cannot connect db: %w", err)
	}

	if err = db.AutoMigrate(&model.User{}); err != nil {
		return nil, fmt.Errorf("failed to migrate db: %w", err)
	}

	return db, nil
}

func (s *Server) initLogger() (*zap.Logger, error) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		return nil, fmt.Errorf("cannot init ZAP log: %w", err)
	}

	return logger, nil
}

func (s *Server) globalMiddleware() {
	s.router.Use(middleware.RequestID)
	s.router.Use(middleware.RealIP)
	s.router.Use(middleware.Logger)
	s.router.Use(middleware.Recoverer)
	s.router.Use(middleware.Heartbeat("/ping"))
	s.router.Use(middleware.Timeout(time.Second * time.Duration(s.cfg.ServerTimeout)))
	s.router.Use(render.SetContentType(render.ContentTypeJSON))
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) routes() {
	// s.router.Get("/api/", s.handleAPI())
	// s.router.Get("/about", s.handleAbout())
	// s.router.Get(“/", s.handleIndex())

	authJWT := jwt.NewJWT(s.cfg)
	userRepo := repo.NewUser(s.db)
	authAPI := handler.NewAuth(authJWT, userRepo, s.cfg, appValidator.New())

	s.router.Mount("/auth", authAPI.Router(s.router))
	s.router.Group(func(r chi.Router) {
		r.Use(authJWT.Verifier())
		r.Use(jwt.Authenticator)

		// r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
		// 	_, claims, _ := jwtauth.FromContext(r.Context())
		// 	fmt.Println(claims) // nolint
		// 	render.JSON(w, r, http.NoBody)
		// })
	})
}
