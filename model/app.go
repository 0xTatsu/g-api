package model

import (
	"github.com/0xTatsu/mvtn-api/handler/res"
	"github.com/go-pg/pg/v10"

	"github.com/0xTatsu/mvtn-api/config"
)

type Validator interface {
	Validate(input interface{}) []*res.ErrorItem
}

type App struct {
	Cfg       *config.Configuration
	Validator Validator
	DB        *pg.DB
}
