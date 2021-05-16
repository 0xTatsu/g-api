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
	Secret              string `mapstructure:"jwt_secret,omitempty"`
	HttpCookieKey       string `mapstructure:"http_cookie_key,omitempty"`
	ExpiryInHour        int    `mapstructure:"jwt_expiry_in_hour,omitempty"`
	RefreshExpiryInHour int    `mapstructure:"jwt_refresh_expiry_in_hour,omitempty"`
}

type Application struct {
	SwaggerUIPath string `mapstructure:"swagger_ui_path,omitempty"`
}
