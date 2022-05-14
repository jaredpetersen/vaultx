package k8s_test

import (
	"context"

	"github.com/jaredpetersen/vaultx/api"
)

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
