package auth_test

import (
	"context"

	"github.com/jaredpetersen/vaultx/api"
	"github.com/jaredpetersen/vaultx/auth"
)

const apiPathRenew = "/v1/auth/token/renew-self"

// fakeAPI is a test fake for auth.API.
type fakeAPI struct {
	writeFunc func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error)
}

func (f fakeAPI) Write(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
	return f.writeFunc(ctx, path, vaultToken, payload)
}

// fakeMethod is a test fake for auth.Method.
type fakeMethod struct {
	loginFunc func(ctx context.Context, api auth.API) (auth.Token, error)
}

func (f fakeMethod) Login(ctx context.Context, api auth.API) (auth.Token, error) {
	return f.loginFunc(ctx, api)
}
