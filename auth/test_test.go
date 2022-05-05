package auth_test

import (
	"context"

	"github.com/jaredpetersen/vaultx/api"
)

const apiPathRenew = "/v1/auth/token/renew-self"

type fakeAPI struct {
	writeFunc func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error)
}

func (s fakeAPI) Write(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
	return s.writeFunc(ctx, path, vaultToken, payload)
}
