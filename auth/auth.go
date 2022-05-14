// Package auth contains all the functionality necessary for authenticating with Vault.
//
// See https://www.vaultproject.io/api-docs/auth for more information.
package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jaredpetersen/vaultx/api"
)

// Token represents a Vault authentication token.
//
// This is used throughout vaultx to authenticate with Vault.
type Token struct {
	// Value is a string representation of the token, used when interacting with the Vault Client.
	Value string
	// Expiration indicates when the token expires and must be renewed or regenerated.
	Expiration time.Duration
	// Renewable indicates whether the token can be renewed or must be regenerated.
	Renewable bool
}

// TokenManager manages Vault auth tokens.
type TokenManager interface {
	// SetToken sets the Vault auth token.
	SetToken(token Token)
	// GetToken returns the Vault auth token.
	GetToken() Token
}

// Method represents a way of authenticating against Vault using one of the officially supported techniques.
//
// For more information, see https://www.vaultproject.io/docs/auth
type Method interface {
	Login(ctx context.Context, api api.API) (Token, error)
}

// Event is used to communicate authentication happenings.
type Event struct {
	// Type indicates the type of the authentication event, either "login" or "renew".
	Type string
	// Err indicates when there was a problem authenticating with Vault.
	Err error
}

// Client is the gateway into the auth functionality provided by Vault.
type Client struct {
	API        api.API
	AuthMethod Method
	token      Token
	tokenMtx   sync.RWMutex
}

const httpPathAuthTokenRenewSelf = "/v1/auth/token/renew-self"

// SetToken sets the internal Vault auth token that the client uses to communicate with Vault.
//
// This should be called after authenticating with Vault so that the client may make requests.
func (c *Client) SetToken(token Token) {
	c.tokenMtx.Lock()
	defer c.tokenMtx.Unlock()
	c.token = token
}

// GetToken returns the internal Vault auth token that the client uses to communicate with Vault.
func (c *Client) GetToken() Token {
	c.tokenMtx.RLock()
	defer c.tokenMtx.RUnlock()
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
	token := c.GetToken()
	if token.Value == "" {
		return errors.New("token must be set first")
	}
	if !token.Renewable {
		return errors.New("token is not renewable")
	}

	res, err := c.API.Write(ctx, httpPathAuthTokenRenewSelf, c.GetToken().Value, nil)
	if err != nil {
		return fmt.Errorf("failed to perform renewedToken renewal request: %w", err)
	}

	if res.StatusCode != 200 {
		return fmt.Errorf("received invalid status code %d for http request", res.StatusCode)
	}

	type authResponse struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
	}

	type authResponseWrapper struct {
		Auth authResponse `json:"auth"`
	}

	resBody := new(authResponseWrapper)
	err = res.JSON(resBody)
	if err != nil {
		return fmt.Errorf("failed to map request response: %w", err)
	}

	renewedToken := Token{
		Value:      resBody.Auth.ClientToken,
		Expiration: time.Duration(resBody.Auth.LeaseDuration) * time.Second,
		Renewable:  resBody.Auth.Renewable,
	}
	c.SetToken(renewedToken)

	return nil
}

// Automatic handles login and renewal automatically for you in the background using the configured auth method.
//
// Tokens are renewed 5 seconds before expiration if eligible. If a lease is less than 5 seconds long, the token will
// be replaced instead of attempting renewal.
//
// All login and renewal events and any associated errors are sent to the returned events channel. This channel haas a
// buffer of 1 to help the event receiver keep up with the events. If the channel is ignored or events are not
// received quickly enough, events will be dropped and not sent to the channel to avoid impeding the authentication
// process.
//
// In the event that the context is canceled, login and renewals will be halted and the events channel will be closed.
func (c *Client) Automatic(ctx context.Context) <-chan Event {
	events := make(chan Event, 1)
	c.automaticHelper(ctx, events)
	return events
}

// automaticHelper recursively performs a login or token renew action against Vault and sends any relevant events to
// the provided events channel.
func (c *Client) automaticHelper(ctx context.Context, events chan<- Event) {
	// Non-blocking write to events channel
	write := func(event Event) {
		select {
		case events <- event:
			// Event written to channel successfully
		default:
			// Channel is full, drop the event
		}
	}
	// Login action
	login := func() {
		err := c.Login(ctx)
		if err != nil {
			write(Event{Type: "login", Err: fmt.Errorf("failed to generate new token: %w", err)})
		} else {
			write(Event{Type: "login"})
		}
	}
	// Renew action
	renew := func() {
		err := c.RenewSelf(ctx)
		if err != nil {
			write(Event{Type: "renew", Err: fmt.Errorf("failed to renew token: %w", err)})
		} else {
			write(Event{Type: "renew"})
		}
	}
	// Schedule the provided auth function in the future and then kick off recursion
	schedule := func(after time.Duration, auth func()) {
		timer := time.NewTimer(after)
		go func() {
			select {
			case <-timer.C:
				auth()
				c.automaticHelper(ctx, events)
			case <-ctx.Done():
				timer.Stop()
				close(events)
				return
			}
		}()
	}

	token := c.GetToken()
	renewable := token.Renewable

	// Get fresh Vault authentication 5 seconds before the token's expiration
	// If this produces a negative schedule time, the token should not be renewed and the login action should be taken
	waitRefresh := token.Expiration - 5*time.Second
	if waitRefresh < 0 {
		renewable = false
		waitRefresh = 0
	}

	if renewable {
		schedule(waitRefresh, renew)
	} else {
		schedule(waitRefresh, login)
	}
}
