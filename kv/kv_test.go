package kv_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jaredpetersen/vaultx/api"
	"github.com/jaredpetersen/vaultx/auth"
	"github.com/jaredpetersen/vaultx/internal/testcontainervault"
	"github.com/jaredpetersen/vaultx/kv"
)

func TestGetSecretReturnsSecret(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		Value: "vault token",
	}
	tokenManager := fakeTokenManager{}
	tokenManager.getTokenFunc = func() auth.Token {
		return token
	}

	secretData := map[string]interface{}{
		"username": "dbuser",
		"password": "3hvu2ZLxwauHrNaZjJbJARHE",
	}
	secretVersion := 251
	secretPath := "mypath"

	// Set up mock API
	apic := fakeAPI{}
	apic.readFunc = func(ctx context.Context, path string, vaultToken string) (*api.Response, error) {
		if path == "/v1/secret/data/"+secretPath && vaultToken == token.Value {
			resBody := fmt.Sprintf(
				"{\"data\": {\"data\": {\"username\": \"%s\", \"password\": \"%s\"}, \"metadata\": {\"version\": %d}}}",
				secretData["username"],
				secretData["password"],
				secretVersion)
			res := api.Response{
				StatusCode: 200,
				RawBody:    io.NopCloser(strings.NewReader(resBody)),
			}
			return &res, nil
		}
		return nil, nil
	}

	kvc := kv.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	expectedSecret := kv.Secret{
		Data:    secretData,
		Version: secretVersion,
	}

	secret, err := kvc.GetSecret(ctx, secretPath)
	require.NoError(t, err, "Get failure")
	require.NotEmpty(t, secret, "Empty secret")
	require.Equal(t, expectedSecret, *secret, "Incorrect secret")
}

func TestGetSecretReturnsErrorOnRequestFailure(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		Value: "vault token",
	}
	tokenManager := fakeTokenManager{}
	tokenManager.getTokenFunc = func() auth.Token {
		return token
	}

	// Set up mocked API request error
	resErr := errors.New("failed request")

	secretPath := "mypath"

	// Set up mock API
	apic := fakeAPI{}
	apic.readFunc = func(ctx context.Context, path string, vaultToken string) (*api.Response, error) {
		if path == "/v1/secret/data/"+secretPath && vaultToken == token.Value {
			return nil, resErr
		}
		return nil, nil
	}

	kvc := kv.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	secret, err := kvc.GetSecret(ctx, secretPath)
	require.Error(t, err, "Error does not exist")
	require.ErrorIs(t, err, resErr, "Error is incorrect")
	require.Empty(t, secret, "Secret is not empty")
}

func TestGetSecretReturnsErrorOnInvalidResponseCode(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		Value: "vault token",
	}
	tokenManager := fakeTokenManager{}
	tokenManager.getTokenFunc = func() auth.Token {
		return token
	}

	secretData := map[string]interface{}{
		"username": "dbuser",
		"password": "3hvu2ZLxwauHrNaZjJbJARHE",
	}
	secretVersion := 251
	secretPath := "mypath"

	// Set up mock API
	apic := fakeAPI{}
	apic.readFunc = func(ctx context.Context, path string, vaultToken string) (*api.Response, error) {
		if path == "/v1/secret/data/"+secretPath && vaultToken == token.Value {
			resBody := fmt.Sprintf(
				"{\"data\": {\"data\": {\"username\": \"%s\", \"password\": \"%s\"}, \"metadata\": {\"version\": %d}}}",
				secretData["username"],
				secretData["password"],
				secretVersion)
			res := api.Response{
				StatusCode: 418,
				RawBody:    io.NopCloser(strings.NewReader(resBody)),
			}
			return &res, nil
		}
		return nil, nil
	}

	kvc := kv.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	secret, err := kvc.GetSecret(ctx, secretPath)
	require.Error(t, err, "Error does not exist")
	require.Errorf(t, err, "received invalid status code 418 for http request")
	require.Empty(t, secret, "Secret is not empty")
}

func TestGetSecretReturnsErrorOnInvalidJSONResponse(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		Value: "vault token",
	}
	tokenManager := fakeTokenManager{}
	tokenManager.getTokenFunc = func() auth.Token {
		return token
	}

	secretPath := "mypath"

	// Set up mock API
	apic := fakeAPI{}
	apic.readFunc = func(ctx context.Context, path string, vaultToken string) (*api.Response, error) {
		if path == "/v1/secret/data/"+secretPath && vaultToken == token.Value {
			resBody := "a}"
			res := api.Response{
				StatusCode: 200,
				RawBody:    io.NopCloser(strings.NewReader(resBody)),
			}
			return &res, nil
		}
		return nil, nil
	}

	kvc := kv.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	secret, err := kvc.GetSecret(ctx, secretPath)
	require.Error(t, err, "Error does not exist")
	require.Empty(t, secret, "Secret is not empty")
}

func TestUpsertSecretDoesNotReturnError(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		Value: "vault token",
	}
	tokenManager := fakeTokenManager{}
	tokenManager.getTokenFunc = func() auth.Token {
		return token
	}

	secretPath := "mypath"
	secretData := map[string]interface{}{
		"username": "dbuser",
		"password": "3hvu2ZLxwauHrNaZjJbJARHE",
	}

	// Set up mock API
	apic := fakeAPI{}
	apic.writeFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == "/v1/secret/data/"+secretPath && vaultToken == token.Value && payload != nil {
			expectedReqBody := fmt.Sprintf(
				"{\"data\": {\"username\": \"%s\", \"password\": \"%s\"}}",
				secretData["username"],
				secretData["password"])
			actualReqBody, _ := json.Marshal(payload)
			assert.JSONEq(t, expectedReqBody, string(actualReqBody))

			resBody := "{\"data\": {\"version\": 493}}"
			res := api.Response{
				StatusCode: 200,
				RawBody:    io.NopCloser(strings.NewReader(resBody)),
			}
			return &res, nil
		}
		return nil, nil
	}

	kvc := kv.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	err := kvc.UpsertSecret(ctx, secretPath, secretData)
	require.NoError(t, err, "Upsert failure")
}

func TestUpsertSecretReturnsErrorOnRequestFailure(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		Value: "vault token",
	}
	tokenManager := fakeTokenManager{}
	tokenManager.getTokenFunc = func() auth.Token {
		return token
	}

	secretPath := "mypath"
	secretData := map[string]interface{}{
		"username": "dbuser",
		"password": "3hvu2ZLxwauHrNaZjJbJARHE",
	}

	// Set up mocked API request error
	resErr := errors.New("failed request")

	// Set up mock API
	apic := fakeAPI{}
	apic.writeFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == "/v1/secret/data/"+secretPath && vaultToken == token.Value {
			return nil, resErr
		}
		return nil, nil
	}

	kvc := kv.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	err := kvc.UpsertSecret(ctx, secretPath, secretData)
	require.Error(t, err, "Error does not exist")
	require.ErrorIs(t, err, resErr, "Error is incorrect")
}

func TestUpsertSecretReturnsErrorOnInvalidResponseCode(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		Value: "vault token",
	}
	tokenManager := fakeTokenManager{}
	tokenManager.getTokenFunc = func() auth.Token {
		return token
	}

	secretPath := "mypath"
	secretData := map[string]interface{}{
		"username": "dbuser",
		"password": "3hvu2ZLxwauHrNaZjJbJARHE",
	}

	// Set up mock API
	apic := fakeAPI{}
	apic.writeFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == "/v1/secret/data/"+secretPath && vaultToken == token.Value {
			// Valid body, incorrect status code
			resBody := "{\"data\": {\"version\": 493}}"
			res := api.Response{
				StatusCode: 418,
				RawBody:    io.NopCloser(strings.NewReader(resBody)),
			}
			return &res, nil
		}
		return nil, nil
	}

	kvc := kv.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	err := kvc.UpsertSecret(ctx, secretPath, secretData)
	require.Error(t, err, "Error does not exist")
	require.Errorf(t, err, "received invalid status code 418 for http request")
}

func TestUpsertSecretReturnsErrorOnInvalidJSONResponse(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		Value: "vault token",
	}
	tokenManager := fakeTokenManager{}
	tokenManager.getTokenFunc = func() auth.Token {
		return token
	}

	secretPath := "mypath"
	secretData := map[string]interface{}{
		"username": "dbuser",
		"password": "3hvu2ZLxwauHrNaZjJbJARHE",
	}

	// Set up mock API
	apic := fakeAPI{}
	apic.writeFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == "/v1/secret/data/"+secretPath && vaultToken == token.Value {
			resBody := "a}"
			res := api.Response{
				StatusCode: 200,
				RawBody:    io.NopCloser(strings.NewReader(resBody)),
			}
			return &res, nil
		}
		return nil, nil
	}

	kvc := kv.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	err := kvc.UpsertSecret(ctx, secretPath, secretData)
	require.Error(t, err, "Error does not exist")
}

func TestIntegrationUpsertSecretDoesNotReturnError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	vaultContainer, err := testcontainervault.NewContainer(ctx)
	require.NoError(t, err, "Failed to set up Vault container")
	defer vaultContainer.Terminate(ctx)

	apic := api.Client{
		HTTP: cleanhttp.DefaultClient(),
		URL:  vaultContainer.URI,
	}

	authc := auth.Client{
		API: &apic,
	}
	authc.SetToken(auth.Token{Value: vaultContainer.Token})

	kvc := kv.Client{
		API:          &apic,
		TokenManager: &authc,
	}

	secretPath := "mypath"
	secretData := map[string]interface{}{
		"username": "dbuser",
		"password": "3hvu2ZLxwauHrNaZjJbJARHE",
	}

	err = kvc.UpsertSecret(ctx, secretPath, secretData)
	require.NoError(t, err, "Upsert failure")
}

func TestIntegrationUpsertGetSecretReturnsSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	vaultContainer, err := testcontainervault.NewContainer(ctx)
	require.NoError(t, err, "Failed to set up Vault container")
	defer vaultContainer.Terminate(ctx)

	apic := api.Client{
		HTTP: cleanhttp.DefaultClient(),
		URL:  vaultContainer.URI,
	}

	authc := auth.Client{
		API: &apic,
	}
	authc.SetToken(auth.Token{Value: vaultContainer.Token})

	kvc := kv.Client{
		API:          &apic,
		TokenManager: &authc,
	}

	secretPath := "mypath"
	secretData := map[string]interface{}{
		"username": "dbuser",
		"password": "3hvu2ZLxwauHrNaZjJbJARHE",
	}

	err = kvc.UpsertSecret(ctx, secretPath, secretData)
	require.NoError(t, err, "Upsert failure")

	expectedSecret := kv.Secret{
		Data:    secretData,
		Version: 1,
	}

	secret, err := kvc.GetSecret(ctx, secretPath)
	require.NoError(t, err, "Get failure")
	require.NotEmpty(t, secret, "Secret is empty")
	require.Equal(t, expectedSecret, *secret, "Secret is incorrect")
}

func TestIntegrationGetSecretReturnsEmptyForMissingSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	vaultContainer, err := testcontainervault.NewContainer(ctx)
	require.NoError(t, err, "Failed to set up Vault container")
	defer vaultContainer.Terminate(ctx)

	apic := api.Client{
		HTTP: cleanhttp.DefaultClient(),
		URL:  vaultContainer.URI,
	}

	authc := auth.Client{
		API: &apic,
	}
	authc.SetToken(auth.Token{Value: vaultContainer.Token})

	kvc := kv.Client{
		API:          &apic,
		TokenManager: &authc,
	}

	secretPath := "mypath"

	secret, err := kvc.GetSecret(ctx, secretPath)
	require.NoError(t, err, "Get failure")
	require.Empty(t, secret, "Secret is not empty")
}
