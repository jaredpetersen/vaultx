package kv_test

import (
	"context"
	"regexp"

	"github.com/jaredpetersen/vaultx/api"
	"github.com/jaredpetersen/vaultx/auth"
)

const apiPathSecret = "/v1/secret/data/"

var apiPathKVRegex = regexp.MustCompile("/v1/secret/data/([A-Za-z]+)")

// FakeAPI is a test fake for auth.API.
type FakeAPI struct {
	WriteFunc func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error)
	ReadFunc  func(ctx context.Context, path string, vaultToken string) (*api.Response, error)
}

func (m FakeAPI) Write(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
	return m.WriteFunc(ctx, path, vaultToken, payload)
}

func (m FakeAPI) Read(ctx context.Context, path string, vaultToken string) (*api.Response, error) {
	return m.ReadFunc(ctx, path, vaultToken)
}

// FakeTokenManager is a test fake for auth.TokenManager.
type FakeTokenManager struct {
	setTokenFunc func(token auth.Token)
	getTokenFunc func() auth.Token
}

func (f FakeTokenManager) SetToken(token auth.Token) {
	f.setTokenFunc(token)
}

func (f FakeTokenManager) GetToken() auth.Token {
	return f.getTokenFunc()
}
