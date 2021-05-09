package config

import (
	"fmt"
	"log"

	"github.com/spf13/viper"
)

func New() (*Configuration, error) {
	viper.SetConfigType("yaml")
	viper.SetConfigName("env")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		log.Printf("There is no config file, reading from env variables: %s", err)
	}

	var cfg Configuration
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unable to decode into struct, %w", err)
	}

	return &cfg, nil
}

// Configuration holds data necessary for configuring application
type Configuration struct {
	Server *Server      `mapstructure:"server,omitempty"`
	DB     *Database    `mapstructure:"database,omitempty"`
	JWT    *JWT         `mapstructure:"jwt,omitempty"`
	App    *Application `mapstructure:"application,omitempty"`
}

type Database struct {
	LogQueries bool `mapstructure:"log_queries,omitempty"`
	Timeout    int  `mapstructure:"timeout_seconds,omitempty"`
}

type Server struct {
	Port string `mapstructure:"port,omitempty"`
}

type JWT struct {
	MinSecretLength  int    `mapstructure:"min_secret_length,omitempty"`
	DurationMinutes  int    `mapstructure:"duration_minutes,omitempty"`
	RefreshDuration  int    `mapstructure:"refresh_duration_minutes,omitempty"`
	MaxRefresh       int    `mapstructure:"max_refresh_minutes,omitempty"`
	SigningAlgorithm string `mapstructure:"signing_algorithm,omitempty"`
}

type Application struct {
	SwaggerUIPath string `mapstructure:"swagger_ui_path,omitempty"`
}
