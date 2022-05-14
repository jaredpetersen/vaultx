package transit_test

import (
	"context"

	"github.com/jaredpetersen/vaultx/api"
	"github.com/jaredpetersen/vaultx/auth"
)

// FakeAPI is a test fake for auth.API.
type FakeAPI struct {
	WriteFunc func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error)
	ReadFunc  func(ctx context.Context, path string, vaultToken string) (*api.Response, error)
}

func (f FakeAPI) Write(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
	return f.WriteFunc(ctx, path, vaultToken, payload)
}

func (f FakeAPI) Read(ctx context.Context, path string, vaultToken string) (*api.Response, error) {
	return f.ReadFunc(ctx, path, vaultToken)
}

// FakeTokenManager is a test fake for auth.TokenManager.
type FakeTokenManager struct {
	SetTokenFunc func(token auth.Token)
	GetTokenFunc func() auth.Token
}

func (f FakeTokenManager) SetToken(token auth.Token) {
	f.SetTokenFunc(token)
}

func (f FakeTokenManager) GetToken() auth.Token {
	return f.GetTokenFunc()
}
