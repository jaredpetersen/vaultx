package k8s_test

import (
	"context"
	"errors"

	"github.com/jaredpetersen/vaultx/api"
)

const apiPathKubernetesLogin = "/v1/auth/kubernetes/login"

// MockAPI is a test mock for auth.API. Rather than defining behavior on a strict function basis, behavior is defined on an
// endpoint basis. This makes the mock less fragile since we can add new routes or change the route without breaking
// any existing tests.
type MockAPI struct {
	// KubernetesLoginFunc is called whenever a request is made to log in via the Kubernetes auth method.
	KubernetesLoginFunc func(vaultToken string, payload interface{}) (*api.Response, error)
}

func (m MockAPI) Write(_ context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
	if path == apiPathKubernetesLogin {
		return m.KubernetesLoginFunc(vaultToken, payload)
	}
	return nil, errors.New("not implemented")
}

func (m MockAPI) Read(_ context.Context, path string, vaultToken string) (*api.Response, error) {
	return nil, errors.New("not implemented")
}
