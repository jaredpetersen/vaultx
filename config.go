package vaultx

import (
	"time"

	"github.com/jaredpetersen/vaultx/auth"
)

// Config describes how the Client should be configured.
type Config struct {
	URL  string
	HTTP HTTPConfig
	Auth AuthConfig
}

// HTTPConfig describes how the HTTP client should be configured.
type HTTPConfig struct {
	Timeout time.Duration
}

// AuthConfig describes how the Client should be configured in regard to authentication.
type AuthConfig struct {
	Method auth.Method
}

// NewConfig creates a new configuration struct with some helpful defaults.
func NewConfig(url string) Config {
	return Config{
		URL: url,
		HTTP: HTTPConfig{
			Timeout: 10 * time.Second,
		},
	}
}
