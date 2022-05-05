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
	// Config configures how the Vault client will interact with Vault.
	Config *Config

	http *http.Client

	api     *api.Client
	auth    *auth.Client
	kv      *kv.Client
	transit *transit.Client
	db      *db.Client
}

// API is a direct client to the Vault HTTP engine, enabling manual execution against Vault.
func (c *Client) API() *api.Client {
	return c.api
}

// Auth is a gateway into Vault authentication.
//
// See https://www.vaultproject.io/api-docs/auth for more information.
func (c *Client) Auth() *auth.Client {
	return c.auth
}

// KV is a gateway into the key-value secrets engine.
//
// For more information, see https://www.vaultproject.io/docs/secrets/kv.
func (c *Client) KV() *kv.Client {
	return c.kv
}

// Transit is a gateway into the transit secrets engine.
//
// For more information, see https://www.vaultproject.io/docs/secrets/transit.
func (c *Client) Transit() *transit.Client {
	return c.transit
}

// DB is a gateway into the database secrets engine.
//
// For more information, see https://www.vaultproject.io/docs/secrets/databases.
func (c *Client) DB() *db.Client {
	return c.db
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
		api:     apiClient,
		auth:    authClient,
		kv:      kvClient,
		transit: transitClient,
		db:      dbClient,
	}
}
