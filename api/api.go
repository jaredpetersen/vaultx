// Package api provides functionality for making requests against the Vault API. This can be used by clients to
// perform actions manually that are not yet supported by vaultx.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// API makes requests against the Vault API.
type API interface {
	// Write sends data to the Vault API.
	Write(ctx context.Context, path string, vaultToken string, payload interface{}) (*Response, error)

	// Read retrieves data from the Vault API.
	Read(ctx context.Context, path string, vaultToken string) (*Response, error)
}

// Client executes actions against the Vault API manually.
//
// This is primarily used by the various vaultx clients to communicate with Vault but can also be used by consumers
// for functionality not yet implemented by the package.
type Client struct {
	HTTP *http.Client
	URL  string
}

type Response struct {
	StatusCode int
	RawBody    io.ReadCloser
}

func (r *Response) JSON(v interface{}) error {
	defer r.RawBody.Close()
	return json.NewDecoder(r.RawBody).Decode(v)
}

func (c *Client) Write(ctx context.Context, path string, vaultToken string, payload interface{}) (*Response, error) {
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+path, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}

	if vaultToken != "" {
		req.Header.Set("x-vault-token", vaultToken)
	}

	req.Header.Set("content-type", "application/json")

	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform http request: %w", err)
	}

	return &Response{StatusCode: res.StatusCode, RawBody: res.Body}, nil
}

func (c *Client) Read(ctx context.Context, path string, vaultToken string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http request %w", err)
	}

	if vaultToken != "" {
		req.Header.Set("x-vault-token", vaultToken)
	}

	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform http request: %w", err)
	}

	return &Response{StatusCode: res.StatusCode, RawBody: res.Body}, nil
}
