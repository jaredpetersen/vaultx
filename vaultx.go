package vaultx

import (
	"net/http"
	"strings"

	"github.com/hashicorp/go-cleanhttp"

	"github.com/jaredpetersen/vaultx/api"
	"github.com/jaredpetersen/vaultx/auth"
	"github.com/jaredpetersen/vaultx/db"
	"github.com/jaredpetersen/vaultx/kv"
	"github.com/jaredpetersen/vaultx/transit"
)

// Client is a resource for interacting with Vault.
type Client struct {
	http *http.Client

	// Config configures how the Vault client will interact with Vault.
	Config *Config

	// API is a direct client to the Vault HTTP engine, enabling manual execution against Vault.
	API *api.Client

	// Auth is a gateway into Vault authentication.
	//
	// See https://www.vaultproject.io/api-docs/auth for more information.
	Auth *auth.Client

	// KV is a gateway into the key-value secrets engine.
	//
	// For more information, see https://www.vaultproject.io/docs/secrets/kv.
	KV *kv.Client

	// Transit is a gateway into the transit secrets engine.
	//
	// For more information, see https://www.vaultproject.io/docs/secrets/transit.
	Transit *transit.Client

	// DB is a gateway into the database secrets engine.
	//
	// For more information, see https://www.vaultproject.io/docs/secrets/databases.
	DB *db.Client
}

// New creates a new Vault client.
func New(config Config) *Client {
	// Remove trailing slash if present, just for predictability with building urls
	config.URL = strings.TrimSuffix(config.URL, "/")

	httpClient := cleanhttp.DefaultClient()
	httpClient.Timeout = config.HTTP.Timeout

	apiClient := &api.Client{
		HTTP: httpClient,
		URL:  config.URL,
	}

	authClient := &auth.Client{
		API:        apiClient,
		AuthMethod: config.Auth.Method,
	}

	kvClient := &kv.Client{
		API:          apiClient,
		TokenManager: authClient,
	}

	transitClient := &transit.Client{
		API:          apiClient,
		TokenManager: authClient,
	}

	dbClient := &db.Client{
		API:          apiClient,
		TokenManager: authClient,
	}

	return &Client{
		Config:  &config,
		http:    httpClient,
		API:     apiClient,
		Auth:    authClient,
		KV:      kvClient,
		Transit: transitClient,
		DB:      dbClient,
	}
}
