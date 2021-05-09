package config

import (
	"log"

	"github.com/spf13/viper"
)

func New() *Configuration {
	viper.SetConfigType("yaml")
	viper.SetConfigName("env")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("There is no config file, reading from env variables: %s", err)
	}

	var cfg Configuration
	if err := viper.Unmarshal(&cfg); err != nil {
		log.Fatalf("unable to decode into struct, %s", err)
	}

	return &cfg
}

// Configuration holds data necessary for configuring application
type Configuration struct {
	Server *Server      `mapstructure:"server,omitempty"`
	DB     *Database    `mapstructure:"database,omitempty"`
	JWT    *JWT         `mapstructure:"jwt,omitempty"`
	App    *Application `mapstructure:"application,omitempty"`
}

type Database struct {
	User string `mapstructure:"db_user,omitempty"`
	Pass string `mapstructure:"db_pass,omitempty"`
	Addr string `mapstructure:"db_addr,omitempty"`
}

type Server struct {
	Port    string `mapstructure:"port,omitempty"`
	Address string `mapstructure:"address,omitempty"`
	Timeout int    `mapstructure:"timeout_seconds,omitempty"`
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
