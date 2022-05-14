// Package kv contains all the functionality necessary for interacting with Vault's KV secrets engine.
//
// See https://www.vaultproject.io/docs/secrets/kv for more information.
package kv

import (
	"context"
	"fmt"

	"github.com/jaredpetersen/vaultx/api"
	"github.com/jaredpetersen/vaultx/auth"
)

// Client is the gateway into Vault's key-value secrets engine.
type Client struct {
	API          api.API
	TokenManager auth.TokenManager
}

// Secret contains versioned, private information corresponding to a key in Vault's key-value engine.
type Secret struct {
	Data    map[string]interface{}
	Version int
}

const httpPathKVSecret = "/v1/secret/data/"

// GetSecret retrieves the secret at the specified path and maps the data a struct at the provided address.
//
// If a secret is not found at the provided path, nil will be returned for both the secret and error return values.
func (c *Client) GetSecret(ctx context.Context, secretPath string) (*Secret, error) {
	type responseMetadata struct {
		Version int `json:"version"`
	}

	type response struct {
		Data     map[string]interface{} `json:"data"`
		Metadata responseMetadata       `json:"metadata"`
	}

	type responseWrapper struct {
		Data response `json:"data"`
	}

	res, err := c.API.Read(ctx, httpPathKVSecret+secretPath, c.TokenManager.GetToken().Value)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	if res.StatusCode == 404 {
		// Secret does not exist
		return nil, nil
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("received invalid status code %d for http request", res.StatusCode)
	}

	resBody := new(responseWrapper)
	err = res.JSON(resBody)
	if err != nil {
		return nil, err
	}

	secret := Secret{
		Data:    resBody.Data.Data,
		Version: resBody.Data.Metadata.Version,
	}

	return &secret, nil
}

// UpsertSecret creates or updates the secret at the specified path.
func (c *Client) UpsertSecret(ctx context.Context, secretPath string, secret map[string]interface{}) error {
	type requestWrapper struct {
		Data map[string]interface{} `json:"data"`
	}

	req := requestWrapper{
		Data: secret,
	}

	res, err := c.API.Write(ctx, httpPathKVSecret+secretPath, c.TokenManager.GetToken().Value, req)
	if err != nil {
		return fmt.Errorf("failed to store secret: %w", err)
	}

	if res.StatusCode != 200 {
		return fmt.Errorf("received invalid status code %d for http request", res.StatusCode)
	}

	type response struct {
		Version int `json:"version"`
	}

	type responseWrapper struct {
		Data response `json:"data"`
	}

	resBody := new(responseWrapper)
	err = res.JSON(resBody)
	if err != nil {
		return err
	}

	return nil
}
