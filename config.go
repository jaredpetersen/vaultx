package vaultx

import (
	"time"

	"github.com/jaredpetersen/vaultx/auth"
)

type Config struct {
	URL  string
	HTTP HTTPConfig
	Auth AuthConfig
}

type HTTPConfig struct {
	Timeout time.Duration
}

type AuthConfig struct {
	Method auth.Method
}

func NewConfig(url string) Config {
	return Config{
		URL: url,
		HTTP: HTTPConfig{
			Timeout: 10 * time.Second,
		},
	}
}
