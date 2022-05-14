package db_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jaredpetersen/vaultx/api"
	"github.com/jaredpetersen/vaultx/auth"
	"github.com/jaredpetersen/vaultx/db"
	"github.com/jaredpetersen/vaultx/internal/testcontainerpostgres"
	"github.com/jaredpetersen/vaultx/internal/testcontainervault"
)

func TestGenerateCredentialsReturnsCredentials(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		Value: "vault token",
	}
	tokenManager := fakeTokenManager{}
	tokenManager.getTokenFunc = func() auth.Token {
		return token
	}

	generatedLeaseID := "somelease"
	generatedLeaseExpiration := 400
	generatedLeaseRenewable := true
	generatedUsername := "someusername"
	generatedPassword := "somepassword"

	dbRole := "dbrole"

	// Set up mock API
	apic := fakeAPI{}
	apic.readFunc = func(ctx context.Context, path string, vaultToken string) (*api.Response, error) {
		if path == "/v1/database/creds/"+dbRole && vaultToken == token.Value {
			resBodyFmt := `{
				"lease_id": "%s",
				"lease_duration": %d,
				"renewable": %t,
				"data": {
					"username": "%s",
					"password": "%s"
				}
			}`
			resBody := fmt.Sprintf(
				resBodyFmt,
				generatedLeaseID,
				generatedLeaseExpiration,
				generatedLeaseRenewable,
				generatedUsername,
				generatedPassword)
			res := api.Response{
				StatusCode: 200,
				RawBody:    io.NopCloser(strings.NewReader(resBody)),
			}
			return &res, nil
		}
		return nil, nil
	}

	dbc := db.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	dbCredentials, err := dbc.GenerateCredentials(ctx, dbRole)
	require.NoError(t, err, "Credential generation failure")
	require.NotEmpty(t, dbCredentials, "Credentials are empty")
	assert.Equal(t, generatedUsername, dbCredentials.Username, "Username is incorrect")
	assert.Equal(t, generatedPassword, dbCredentials.Password, "Password is incorrect")
	assert.Equal(t, generatedLeaseID, dbCredentials.Lease.ID, "Lease ID is incorrect")
	assert.Equal(t, generatedLeaseRenewable, dbCredentials.Lease.Renewable, "Lease renewable is incorrect")
	assert.Equal(t, time.Duration(generatedLeaseExpiration)*time.Second, dbCredentials.Lease.Expiration, "Lease expiration is incorrect")
}

func TestGenerateCredentialsReturnsErrorOnRequestFailure(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		Value: "vault token",
	}
	tokenManager := fakeTokenManager{}
	tokenManager.getTokenFunc = func() auth.Token {
		return token
	}

	dbRole := "dbrole"

	// Set up mocked API request error
	resErr := errors.New("failed request")

	// Set up mock API
	apic := fakeAPI{}
	apic.readFunc = func(ctx context.Context, path string, vaultToken string) (*api.Response, error) {
		if path == "/v1/database/creds/"+dbRole && vaultToken == token.Value {
			return nil, resErr
		}
		return nil, nil
	}

	dbc := db.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	dbCredentials, err := dbc.GenerateCredentials(ctx, dbRole)
	require.ErrorIs(t, err, resErr, "Error is incorrect")
	require.Empty(t, dbCredentials, "Credentials are not empty")
}

func TestGenerateCredentialsReturnsErrorOnInvalidResponseCode(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		Value: "vault token",
	}
	tokenManager := fakeTokenManager{}
	tokenManager.getTokenFunc = func() auth.Token {
		return token
	}

	dbRole := "dbrole"

	// Set up mock API
	apic := fakeAPI{}
	apic.readFunc = func(ctx context.Context, path string, vaultToken string) (*api.Response, error) {
		if path == "/v1/database/creds/"+dbRole && vaultToken == token.Value {
			// Valid body but incorrect status code
			resBody := `{
				"lease_id": "someid",
				"lease_duration": 300,
				"renewable": true,
				"data": {
					"username": "someusername",
					"password": "somepassword"
				}
			}`
			res := api.Response{
				StatusCode: 418,
				RawBody:    io.NopCloser(strings.NewReader(resBody)),
			}
			return &res, nil
		}
		return nil, nil
	}

	dbc := db.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	dbCredentials, err := dbc.GenerateCredentials(ctx, dbRole)
	require.Error(t, err, "Error does not exist")
	require.Errorf(t, err, "received invalid status code 418 for http request")
	require.Empty(t, dbCredentials, "Credentials are not empty")
}

func TestGenerateCredentialsReturnsErrorOnInvalidJSONResponse(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		Value: "vault token",
	}
	tokenManager := fakeTokenManager{}
	tokenManager.getTokenFunc = func() auth.Token {
		return token
	}

	dbRole := "dbrole"

	// Set up mock API
	apic := fakeAPI{}
	apic.readFunc = func(ctx context.Context, path string, vaultToken string) (*api.Response, error) {
		if path == "/v1/database/creds/"+dbRole && vaultToken == token.Value {
			resBody := "a}"
			res := api.Response{
				StatusCode: 200,
				RawBody:    io.NopCloser(strings.NewReader(resBody)),
			}
			return &res, nil
		}
		return nil, nil
	}

	dbc := db.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	dbCredentials, err := dbc.GenerateCredentials(ctx, dbRole)
	require.Error(t, err, "Error does not exist")
	require.Empty(t, dbCredentials, "Credentials are not empty")
}

func TestIntegrationGenerateCredentialsReturnsCredentials(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	dbUser := "testytesty"
	dbPassword := "password"
	dbName := "testydb"
	dbContainer, err := testcontainerpostgres.NewContainer(ctx, dbUser, dbPassword, dbName)
	require.NoError(t, err, "Failed to set up database container")
	defer dbContainer.Terminate(ctx)

	vaultContainer, err := testcontainervault.NewContainer(ctx)
	require.NoError(t, err, "Failed to set up Vault container")
	defer vaultContainer.Terminate(ctx)

	err = vaultContainer.EnableDBEngine(ctx)
	require.NoError(t, err, "Failed to initialize Vault container")

	dbRole := "dbrole"
	err = vaultContainer.CreateDBEngineRole(ctx, dbRole, dbName)
	require.NoError(t, err, "Failed to set up Vault database engine role")

	dbContainerIP, err := dbContainer.ContainerIP(ctx)
	require.NoError(t, err, "Failed to get database container IP")

	dbURITemplate := fmt.Sprintf(
		"postgresql://{{username}}:{{password}}@%s:5432/postgres?sslmode=disable",
		dbContainerIP)
	err = vaultContainer.CreateDBEngineConfig(ctx, dbName, dbURITemplate, dbUser, dbPassword, dbRole)
	require.NoError(t, err, "Failed to set up Vault database engine config")

	apic := api.Client{
		HTTP: cleanhttp.DefaultClient(),
		URL:  vaultContainer.URI,
	}

	authc := auth.Client{
		API: &apic,
	}
	authc.SetToken(auth.Token{Value: vaultContainer.Token})

	dbc := db.Client{
		API:          &apic,
		TokenManager: &authc,
	}

	dbCredentials, err := dbc.GenerateCredentials(ctx, dbRole)
	require.NoError(t, err, "Credential generation failure")
	require.NotEmpty(t, dbCredentials, "Credentials are empty")
	assert.NotEmpty(t, dbCredentials.Username, "Username is empty")
	assert.NotEqual(t, dbUser, dbCredentials.Username, "Username matches original credentials")
	assert.True(t, strings.HasPrefix(dbCredentials.Username, "v-token-"+dbRole))
	assert.NotEmpty(t, dbCredentials.Password, "Password is empty")
	assert.NotEqual(t, dbPassword, dbCredentials.Password, "Password matches original credentials")
	assert.NotEmpty(t, dbCredentials.Lease.ID, "Lease ID is empty")
	assert.True(t, dbCredentials.Lease.Renewable, "Lease is not renewable")
	assert.NotEmpty(t, dbCredentials.Lease.Expiration, "Lease expiration is empty")
}

func TestIntegrationGenerateCredentialsReturnsErrorOnInvalidDBEngineConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	dbUser := "testytesty"
	dbPassword := "password"
	dbName := "testydb"
	dbContainer, err := testcontainerpostgres.NewContainer(ctx, dbUser, dbPassword, dbName)
	require.NoError(t, err, "Failed to set up database container")
	defer dbContainer.Terminate(ctx)

	vaultContainer, err := testcontainervault.NewContainer(ctx)
	require.NoError(t, err, "Failed to set up Vault container")
	defer vaultContainer.Terminate(ctx)

	err = vaultContainer.EnableDBEngine(ctx)
	require.NoError(t, err, "Failed to initialize Vault container")

	apic := api.Client{
		HTTP: cleanhttp.DefaultClient(),
		URL:  vaultContainer.URI,
	}

	authc := auth.Client{
		API: &apic,
	}
	authc.SetToken(auth.Token{Value: vaultContainer.Token})

	dbc := db.Client{
		API:          &apic,
		TokenManager: &authc,
	}

	dbCredentials, err := dbc.GenerateCredentials(ctx, "dbrole")
	require.Error(t, err, "Error does not exist")
	require.Empty(t, dbCredentials, "Credentials are not empty")
}
