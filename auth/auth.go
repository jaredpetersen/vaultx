package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/jaredpetersen/vaultx/api"
)

// Token represents a Vault authentication token.
//
// This is used throughout vaultx to authenticate with Vault.
type Token struct {
	// ClientToken is a string representation of the token, used when interacting with the Vault Client.
	ClientToken string

	// Accessor is a unique identifier for the Vault token but is not useful as an authentication mechanism.
	Accessor string

	// Lease indicates when the token expires and must be renewed or regenerated.
	Lease TokenLease

	// Renewable indicates whether the token can be renewed or must be regenerated.
	Renewable bool
}

// TokenLease provides information about how long the token will last.
type TokenLease struct {
	// Duration indicates when the token expires and must be renewed or regenerated.
	Duration time.Duration

	// Renewable indicates if the lease can be renewed.
	Renewable bool
}

// TokenManager manages Vault auth tokens.
type TokenManager interface {
	// SetToken sets the Vault auth token.
	SetToken(token *Token)

	// GetToken returns the Vault auth token.
	GetToken() *Token
}

// Method represents a way of authenticating against Vault using one of the officially supported techniques.
//
// For more information, see https://www.vaultproject.io/docs/auth
type Method interface {
	Login(ctx context.Context, api api.API) (*Token, error)
}

// Event is used to communicate authentication happenings.
type Event struct {
	// Type indicates the type of the authentication event, either "login" or "renew".
	Type string

	// Err indicates when there was a problem authenticating with Vault.
	Err error
}

// Client is the gateway into the auth functionality provided by Vault.
//
// See https://www.vaultproject.io/api-docs/auth for more information.
type Client struct {
	API        api.API
	AuthMethod Method
	token      *Token
}

const httpPathAuthTokenRenewSelf = "/v1/auth/token/renew-self"

// SetToken sets the internal Vault auth token that the client uses to communicate with Vault.
//
// This should be called after authenticating with Vault so that the client may make requests.
func (c *Client) SetToken(token *Token) {
	c.token = token
}

// GetToken returns the internal Vault auth token that the client uses to communicate with Vault.
func (c *Client) GetToken() *Token {
	return c.token
}

// Login authenticates against Vault using the configured auth method and sets the internal auth token that the client
// uses to communicate with Vault.
func (c *Client) Login(ctx context.Context) error {
	token, err := c.AuthMethod.Login(ctx, c.API)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	c.SetToken(token)

	return nil
}

// RenewSelf initiates a token renewal request for the internal Vault auth token that the client uses to
// communicate with Vault.
//
// See https://www.vaultproject.io/api/auth/token#renew-a-token-self for more information.
func (c *Client) RenewSelf(ctx context.Context) error {
	res, err := c.API.Write(ctx, httpPathAuthTokenRenewSelf, c.GetToken().ClientToken, nil)
	if err != nil {
		return fmt.Errorf("failed to perform token renewal request: %w", err)
	}

	if res.StatusCode != 200 {
		return fmt.Errorf("received invalid status code %d for http request", res.StatusCode)
	}

	type authResponse struct {
		ClientToken string `json:"client_token"`
	}

	type authResponseWrapper struct {
		Auth authResponse `json:"auth"`
	}

	authJSON := new(authResponseWrapper)
	err = res.JSON(authJSON)
	if err != nil {
		return fmt.Errorf("failed to map request response: %w", err)
	}

	return nil
}

// Automatic handles login and renewal automatically for you using the configured auth method.
//
// If there's an issue with authenticating against Vault for the first time, an error will be returned immediately.
// Otherwise, token renewal and replacement will happen automatically in the background using a goroutine and errors
// are completely ignored.
//
// If a log function is provided, authentication events and errors will be provided as an argument.
func (c *Client) Automatic(ctx context.Context, log func(event Event)) error {
	// Establish initial Vault credentials
	err := c.Login(ctx)
	if err != nil {
		return err
	}

	// Initial login event
	log(Event{Type: "login"})

	// Start renewing and re-generating Vault credentials automatically based on the lease period
	c.renewOrReplace(ctx, log)

	return nil
}

// renewOrReplace recursively renews the auth client's token or replaces it if the token lease is no longer renewable.
//
// This is handled through the use of time.AfterFunc, which executes the renew or regeneration logic 10 seconds before
// the token renew time is up.
//
// If an error is encountered, it is logged if applicable and ignored.
func (c *Client) renewOrReplace(ctx context.Context, log func(event Event)) {
	lease := c.GetToken().Lease
	renewTime := lease.Duration - 10*time.Second

	// Stop if the context has been closed
	if ctx.Err() != nil {
		return
	}

	if lease.Renewable && (renewTime > 5*time.Second) {
		// Renew lease
		time.AfterFunc(renewTime, func() {
			err := c.RenewSelf(ctx)
			if err != nil && log != nil {
				log(Event{Type: "renew", Err: fmt.Errorf("failed to renew token: %w", err)})
			} else if log != nil {
				log(Event{Type: "renew"})
			}

			c.renewOrReplace(ctx, log)
		})
	} else {
		// Replace lease
		time.AfterFunc(renewTime, func() {
			err := c.Login(ctx)
			if err != nil && log != nil {
				log(Event{Type: "login", Err: fmt.Errorf("failed to generate new token: %w", err)})
			} else if log != nil {
				log(Event{Type: "login"})
			}

			c.renewOrReplace(ctx, log)
		})
	}
}
