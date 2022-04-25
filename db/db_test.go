package db_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/stretchr/testify/require"

	"github.com/jaredpetersen/vaultx/api"
	apimocks "github.com/jaredpetersen/vaultx/api/mocks"
	"github.com/jaredpetersen/vaultx/auth"
	authmocks "github.com/jaredpetersen/vaultx/auth/mocks"
	"github.com/jaredpetersen/vaultx/db"
	"github.com/jaredpetersen/vaultx/internal/testcontainerpostgres"
	"github.com/jaredpetersen/vaultx/internal/testcontainervault"
)

func TestGenerateCredentialsReturnsCredentials(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		ClientToken: "vault token",
	}
	tokenManager := authmocks.TokenManager{}
	tokenManager.On("GetToken").Return(&token, nil)

	generatedUsername := "someusername"
	generatedPassword := "somepassword"

	// Set up mocked API response
	resBody := fmt.Sprintf(
		"{\"data\": {\"username\": \"%s\", \"password\":\"%s\"}}",
		generatedUsername,
		generatedPassword)
	res := api.Response{
		StatusCode: 200,
		RawBody:    io.NopCloser(strings.NewReader(resBody)),
	}

	dbRole := "dbrole"

	// Set up mock API
	apic := apimocks.API{}
	apic.On("Read", ctx, "/v1/database/creds/"+dbRole, token.ClientToken).Return(&res, nil)

	dbc := db.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	dbCredentials, err := dbc.GenerateCredentials(ctx, dbRole)
	require.NoError(t, err, "Credential generation failure")
	require.NotEmpty(t, dbCredentials, "Credentials are empty")
	require.NotEmpty(t, dbCredentials.Username, "Username is empty")
	require.Equal(t, generatedUsername, dbCredentials.Username, "Username matches original credentials")
	require.NotEmpty(t, dbCredentials.Password, "Password is empty")
	require.Equal(t, generatedPassword, dbCredentials.Password, "Password matches original credentials")
}

func TestGenerateCredentialsReturnsErrorOnRequestFailure(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		ClientToken: "vault token",
	}
	tokenManager := authmocks.TokenManager{}
	tokenManager.On("GetToken").Return(&token, nil)

	// Set up mocked API request error
	resErr := errors.New("failed request")

	dbRole := "dbrole"

	// Set up mock API
	apic := apimocks.API{}
	apic.On("Read", ctx, "/v1/database/creds/"+dbRole, token.ClientToken).Return(nil, resErr)

	dbc := db.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	dbCredentials, err := dbc.GenerateCredentials(ctx, dbRole)
	require.Error(t, err, "Error does not exist")
	require.ErrorIs(t, err, resErr, "Error is incorrect")
	require.Empty(t, dbCredentials, "Credentials are not empty")
}

func TestGenerateCredentialsReturnsErrorOnInvalidResponseCode(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		ClientToken: "vault token",
	}
	tokenManager := authmocks.TokenManager{}
	tokenManager.On("GetToken").Return(&token, nil)

	// Set up mocked API response with valid body but incorrect status code
	resBody := "{\"data\": {\"username\": \"someusername\", \"password\": \"somepassword\"}}"
	res := api.Response{
		StatusCode: 418,
		RawBody:    io.NopCloser(strings.NewReader(resBody)),
	}

	dbRole := "dbrole"

	// Set up mock API
	apic := apimocks.API{}
	apic.On("Read", ctx, "/v1/database/creds/"+dbRole, token.ClientToken).Return(&res, nil)

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
		ClientToken: "vault token",
	}
	tokenManager := authmocks.TokenManager{}
	tokenManager.On("GetToken").Return(&token, nil)

	// Set up mocked API response with invalid JSON
	resBody := "a}"
	res := api.Response{
		StatusCode: 200,
		RawBody:    io.NopCloser(strings.NewReader(resBody)),
	}

	dbRole := "dbrole"

	// Set up mock API
	apic := apimocks.API{}
	apic.On("Read", ctx, "/v1/database/creds/"+dbRole, token.ClientToken).Return(&res, nil)

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
	authc.SetToken(&auth.Token{ClientToken: vaultContainer.Token})

	dbc := db.Client{
		API:          &apic,
		TokenManager: &authc,
	}

	dbCredentials, err := dbc.GenerateCredentials(ctx, dbRole)
	require.NoError(t, err, "Credential generation failure")
	require.NotEmpty(t, dbCredentials, "Credentials are empty")
	require.NotEmpty(t, dbCredentials.Username, "Username is empty")
	require.NotEqual(t, dbUser, dbCredentials.Username, "Username matches original credentials")
	require.True(t, strings.HasPrefix(dbCredentials.Username, "v-token-"+dbRole))
	require.NotEmpty(t, dbCredentials.Password, "Password is empty")
	require.NotEqual(t, dbPassword, dbCredentials.Password, "Password matches original credentials")
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
	authc.SetToken(&auth.Token{ClientToken: vaultContainer.Token})

	dbc := db.Client{
		API:          &apic,
		TokenManager: &authc,
	}

	dbCredentials, err := dbc.GenerateCredentials(ctx, "dbrole")
	require.Error(t, err, "Error does not exist")
	require.Empty(t, dbCredentials, "Credentials are not empty")
}
