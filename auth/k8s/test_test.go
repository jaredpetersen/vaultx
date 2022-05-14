package k8s_test

import (
	"context"

	"github.com/jaredpetersen/vaultx/api"
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
