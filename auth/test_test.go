package auth_test

import (
	"context"

	"github.com/jaredpetersen/vaultx/api"
	"github.com/jaredpetersen/vaultx/auth"
)

const apiPathRenew = "/v1/auth/token/renew-self"
const apiPathKubernetesLogin = "/v1/auth/kubernetes/login"

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

// FakeMethod is a test fake for auth.Method.
type FakeMethod struct {
	loginFunc func(ctx context.Context, api api.API) (auth.Token, error)
}

func (f FakeMethod) Login(ctx context.Context, api api.API) (auth.Token, error) {
	return f.loginFunc(ctx, api)
}
