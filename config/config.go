package config

import (
	"github.com/spf13/viper"
)

func New() (*Env, error) {
	var cfg Env

	viper.SetConfigFile(".env")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return &cfg, err
	}

	err := viper.Unmarshal(&cfg)

	return &cfg, err
}

type Env struct {
	// JWT
	JwtSecret              string `mapstructure:"JWT_SECRET,omitempty"`
	JwtHttpCookieKey       string `mapstructure:"JWT_HTTP_COOKIE_KEY,omitempty"`
	JwtExpiryInHour        int    `mapstructure:"JWT_EXPIRY_IN_HOUR,omitempty"`
	JwtRefreshExpiryInHour int    `mapstructure:"JWT_REFRESH_EXPIRY_IN_HOUR,omitempty"`

	// Database
	DbUrl string `mapstructure:"DATABASE_DNS,omitempty"`

	// Server
	ServerTimeout int    `mapstructure:"SERVER_TIMEOUT_SECONDS,omitempty"`
	ServerPort    string `mapstructure:"SERVER_PORT,omitempty"`
}
