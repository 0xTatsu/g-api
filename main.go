package main

import (
	"log"
	"os"
)

func main() {
	srv := NewServer()

	if err := srv.Start(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

// func main2() {
// 	_, undoReplaceGlobalLog := initLogger()
// 	defer undoReplaceGlobalLog()
//
// 	envCfg, err := config.New()
// 	if err != nil {
// 		log.Print("cannot load config:", err)
// 		return
// 	}
//
// 	db := initDB(envCfg.DBURL)
//
// 	r := chi.NewRouter()
// 	r.Use(middleware.RequestID)
// 	r.Use(middleware.RealIP)
// 	r.Use(middleware.Logger)
// 	r.Use(middleware.Recoverer)
// 	r.Use(middleware.Heartbeat("/ping"))
// 	r.Use(middleware.Timeout(time.Second * time.Duration(envCfg.ServerTimeout)))
// 	r.Use(render.SetContentType(render.ContentTypeJSON))
//
// 	authJWT := jwt.NewJWT(envCfg)
// 	userRepo := repo.NewUser(db)
// 	authAPI := handler.NewAuth(authJWT, userRepo, envCfg, appValidator.New())
//
// 	r.Mount("/auth", authAPI.Router(r))
// 	r.Group(func(r chi.Router) {
// 		r.Use(authJWT.Verifier())
// 		r.Use(jwt.Authenticator)
//
// 		// r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
// 		// 	_, claims, _ := jwtauth.FromContext(r.Context())
// 		// 	fmt.Println(claims) // nolint
// 		// 	render.JSON(w, r, http.NoBody)
// 		// })
// 	})
//
// 	if err := http.ListenAndServe(":"+envCfg.ServerPort, r); err != nil {
// 		log.Panicf("cannot start Server: %s", err)
// 	}
// }
