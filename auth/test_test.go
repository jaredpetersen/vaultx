package auth_test

import (
	"context"
	"errors"

	"github.com/jaredpetersen/vaultx/api"
	"github.com/jaredpetersen/vaultx/auth"
)

const apiPathRenew = "/v1/auth/token/renew-self"

// MockAPI is a test mock for auth.API. Rather than defining behavior on a strict function basis, behavior is defined on an
// endpoint basis. This makes the mock less fragile since we can add new routes or change the route without breaking
// any existing tests.
type MockAPI struct {
	// RenewSelfFunc is called whenever a request is made to renew the client's token.
	RenewSelfFunc func(vaultToken string, payload interface{}) (*api.Response, error)
}

func (m MockAPI) Write(_ context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
	if path == apiPathRenew {
		return m.RenewSelfFunc(vaultToken, payload)
	}
	return nil, errors.New("not implemented")
}

func (m MockAPI) Read(_ context.Context, path string, vaultToken string) (*api.Response, error) {
	return nil, errors.New("not implemented")
}

// FakeMethod is a test fake for auth.Method.
type FakeMethod struct {
	loginFunc func(ctx context.Context, api api.API) (auth.Token, error)
}

func (f FakeMethod) Login(ctx context.Context, api api.API) (auth.Token, error) {
	return f.loginFunc(ctx, api)
}
