package model

import (
	"github.com/go-pg/pg/v10"

	"github.com/0xTatsu/g-api/handler/res"

	"github.com/0xTatsu/g-api/config"
)

type Validator interface {
	Validate(input interface{}) res.Errors
}

type App struct {
	Cfg       *config.Configuration
	Validator Validator
	DB        *pg.DB
}
