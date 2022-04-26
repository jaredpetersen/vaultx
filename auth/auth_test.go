package auth_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jaredpetersen/vaultx/api"
	apimocks "github.com/jaredpetersen/vaultx/api/mocks"
	"github.com/jaredpetersen/vaultx/auth"
	authmocks "github.com/jaredpetersen/vaultx/auth/mocks"
	"github.com/stretchr/testify/require"
)

func TestGetTokenReturnsEmptyToken(t *testing.T) {
	ac := auth.Client{}

	token := ac.GetToken()

	require.Empty(t, token, "Token is not empty")
}

func TestSetGetTokenReturnsToken(t *testing.T) {
	ac := auth.Client{}

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 240 * time.Second,
		Renewable:  false,
	}

	ac.SetToken(token)
	storedToken := ac.GetToken()

	require.Equal(t, token, storedToken, "Token is not the same")
}

func TestLoginUsesAuthMethodToSetToken(t *testing.T) {
	ctx := context.Background()

	api := apimocks.API{}

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 72 * time.Hour,
		Renewable:  true,
	}

	authMethod := authmocks.Method{}
	authMethod.On("Login", ctx, &api).Return(token, nil)

	ac := auth.Client{
		API:        &api,
		AuthMethod: &authMethod,
	}

	err := ac.Login(ctx)
	require.NoError(t, err, "Login failure")

	storedToken := ac.GetToken()
	require.Equal(t, token, storedToken, "Token is incorrect")
}

func TestLoginReturnsErrorOnAuthMethodError(t *testing.T) {
	ctx := context.Background()

	api := apimocks.API{}

	authMethodErr := errors.New("authentication failure")

	authMethod := authmocks.Method{}
	authMethod.On("Login", ctx, &api).Return(auth.Token{Value: "dummy"}, authMethodErr)

	ac := auth.Client{
		API:        &api,
		AuthMethod: &authMethod,
	}

	err := ac.Login(ctx)
	require.Error(t, err, "Error does not exist")
	require.ErrorIs(t, err, authMethodErr, "Incorrect error")

	storedToken := ac.GetToken()
	require.Empty(t, storedToken, "Token is not empty")
}

func TestRenewSelfRenewsTokenAndSetsToken(t *testing.T) {
	ctx := context.Background()

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 30 * time.Minute,
		Renewable:  true,
	}
	renewedToken := auth.Token{
		Value:      "renewedtoken",
		Expiration: 45 * time.Minute,
		Renewable:  false,
	}

	resBody := fmt.Sprintf(
		"{\"auth\": {\"client_token\": \"%s\", \"lease_duration\": %.0f, \"renewable\": %t}}",
		renewedToken.Value,
		renewedToken.Expiration.Seconds(),
		renewedToken.Renewable)
	res := api.Response{
		StatusCode: 200,
		RawBody:    io.NopCloser(strings.NewReader(resBody)),
	}

	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/auth/token/renew-self", token.Value, nil).Return(&res, nil)

	ac := auth.Client{
		API: &apic,
	}

	ac.SetToken(token)
	err := ac.RenewSelf(ctx)
	require.NoError(t, err, "Renew failure")

	storedToken := ac.GetToken()
	require.Equal(t, renewedToken, storedToken, "Token is incorrect")
}

func TestRenewSelfReturnsErrorOnTokenNotSet(t *testing.T) {
	ctx := context.Background()

	apic := apimocks.API{}

	ac := auth.Client{
		API: &apic,
	}

	err := ac.RenewSelf(ctx)
	require.Error(t, err, "Error does not exist")
	require.Errorf(t, err, "token must be set first", "Incorrect error")

	storedToken := ac.GetToken()
	require.Empty(t, storedToken, "Token is incorrect")
}

func TestRenewSelfReturnsErrorOnTokenNotRenewable(t *testing.T) {
	ctx := context.Background()

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 30 * time.Minute,
		Renewable:  false,
	}

	apic := apimocks.API{}

	ac := auth.Client{
		API: &apic,
	}

	ac.SetToken(token)
	err := ac.RenewSelf(ctx)
	require.Error(t, err, "Error does not exist")
	require.Errorf(t, err, "token is not renewable", "Incorrect error")

	storedToken := ac.GetToken()
	require.Equal(t, token, storedToken, "Token is incorrect")
}

func TestRenewSelfReturnsErrorOnRequestFailure(t *testing.T) {
	ctx := context.Background()

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 2 * time.Hour,
		Renewable:  true,
	}

	resErr := errors.New("failed request")

	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/auth/token/renew-self", token.Value, nil).Return(nil, resErr)

	ac := auth.Client{
		API: &apic,
	}

	ac.SetToken(token)
	err := ac.RenewSelf(ctx)
	require.Error(t, err, "Error does not exist")
	require.Error(t, err, resErr, "Error is incorrect")

	storedToken := ac.GetToken()
	require.Equal(t, token, storedToken, "Token is incorrect")
}

func TestRenewSelfReturnsErrorOnInvalidResponseCode(t *testing.T) {
	ctx := context.Background()

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 30 * time.Minute,
		Renewable:  true,
	}
	renewedToken := auth.Token{
		Value:      "renewedtoken",
		Expiration: 45 * time.Minute,
		Renewable:  false,
	}

	resBody := fmt.Sprintf(
		"{\"auth\": {\"client_token\": \"%s\", \"lease_duration\": %.0f, \"renewable\": %t}}",
		renewedToken.Value,
		renewedToken.Expiration.Seconds(),
		renewedToken.Renewable)
	res := api.Response{
		StatusCode: 418,
		RawBody:    io.NopCloser(strings.NewReader(resBody)),
	}

	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/auth/token/renew-self", token.Value, nil).Return(&res, nil)

	ac := auth.Client{
		API: &apic,
	}

	ac.SetToken(token)
	err := ac.RenewSelf(ctx)
	require.Error(t, err, "Error does not exist")
	require.Errorf(t, err, "received invalid status code 418 for http request")

	storedToken := ac.GetToken()
	require.Equal(t, token, storedToken, "Token is incorrect")
}

func TestRenewSelfReturnsErrorOnInvalidJSONResponse(t *testing.T) {
	ctx := context.Background()

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 30 * time.Minute,
		Renewable:  true,
	}

	resBody := "a}"
	res := api.Response{
		StatusCode: 200,
		RawBody:    io.NopCloser(strings.NewReader(resBody)),
	}

	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/auth/token/renew-self", token.Value, nil).Return(&res, nil)

	ac := auth.Client{
		API: &apic,
	}

	ac.SetToken(token)
	err := ac.RenewSelf(ctx)
	require.Error(t, err, "Error does not exist")

	storedToken := ac.GetToken()
	require.Equal(t, token, storedToken, "Token is incorrect")
}
