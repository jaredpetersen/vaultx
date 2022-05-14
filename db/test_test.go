package db_test

import (
	"context"
	"errors"
	"regexp"

	"github.com/jaredpetersen/vaultx/api"
	"github.com/jaredpetersen/vaultx/auth"
)

var apiPathDBCredentialsRegex = regexp.MustCompile("/v1/database/creds/([A-Za-z]+)")

// MockAPI is a test mock for auth.API. Rather than defining behavior on a strict function basis, behavior is defined on an
// endpoint basis. This makes the mock less fragile since we can add new routes or change the route without breaking
// any existing tests.
type MockAPI struct {
	// GenerateDBCredentialsFunc is called whenever a request is made to get generated DB credentials.
	GenerateDBCredentialsFunc func(role string, vaultToken string) (*api.Response, error)
}

func (m MockAPI) Write(_ context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
	return nil, errors.New("not implemented")
}

func (m MockAPI) Read(_ context.Context, path string, vaultToken string) (*api.Response, error) {
	if apiPathDBCredentialsRegex.MatchString(path) {
		return m.GenerateDBCredentialsFunc(apiPathDBCredentialsRegex.FindStringSubmatch(path)[1], vaultToken)
	}
	return nil, errors.New("not implemented")
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
