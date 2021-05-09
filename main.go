package main

import (
	"log"

	"github.com/0xTatsu/mvtn-api/internal/server"
)

func main() {
	s := server.NewApp()
	s.Init()

	if err := s.Run(); err != nil {
		log.Fatalf("canot start server: %s", err)
	}
}
