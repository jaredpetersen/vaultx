package transit_test

import (
	"context"

	"github.com/jaredpetersen/vaultx/api"
	"github.com/jaredpetersen/vaultx/auth"
)

// fakeAPI is a test fake for auth.API.
type fakeAPI struct {
	writeFunc func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error)
	readFunc  func(ctx context.Context, path string, vaultToken string) (*api.Response, error)
}

func (f fakeAPI) Write(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
	return f.writeFunc(ctx, path, vaultToken, payload)
}

func (f fakeAPI) Read(ctx context.Context, path string, vaultToken string) (*api.Response, error) {
	return f.readFunc(ctx, path, vaultToken)
}

// fakeTokenManager is a test fake for auth.TokenManager.
type fakeTokenManager struct {
	setTokenFunc func(token auth.Token)
	getTokenFunc func() auth.Token
}

func (f fakeTokenManager) SetToken(token auth.Token) {
	f.setTokenFunc(token)
}

func (f fakeTokenManager) GetToken() auth.Token {
	return f.getTokenFunc()
}
