package model

import (
	"github.com/go-pg/pg/v10"
	"github.com/go-playground/validator/v10"

	"github.com/0xTatsu/mvtn-api/config"
)

type App struct {
	Cfg       *config.Configuration
	Validator *validator.Validate
	DB        *pg.DB
}
