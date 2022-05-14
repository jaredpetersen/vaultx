package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jaredpetersen/vaultx/auth"

	"github.com/jaredpetersen/vaultx/api"
)

func TestNewKubernetesAuthMethodProvidesDefaultJWTProvider(t *testing.T) {
	kc := auth.KubernetesConfig{Role: "my-role"}
	k := auth.NewKubernetesMethod(kc)

	require.NotEmpty(t, k.Config.JWTProvider, "JWT provider is empty")

	// Can't assert that k.KubernetesConfig.JWTProvider is set to auth.DefaultKubernetesJWTProvider
}

func TestAuthMethodLoginGeneratesToken(t *testing.T) {
	jwt := "jwt"
	kc := auth.KubernetesConfig{
		Role: "my-role",
		JWTProvider: func() (string, error) {
			return jwt, nil
		},
	}
	k := auth.NewKubernetesMethod(kc)

	ctx := context.Background()

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 72 * time.Hour,
		Renewable:  false,
	}

	apic := FakeAPI{}
	apic.WriteFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathKubernetesLogin {
			resBody := fmt.Sprintf(
				"{\"auth\": {\"client_token\": \"%s\", \"lease_duration\": %.0f, \"renewable\": %t}}",
				token.Value,
				token.Expiration.Seconds(),
				token.Renewable)
			res := api.Response{StatusCode: 200, RawBody: io.NopCloser(strings.NewReader(resBody))}
			return &res, nil
		}
		return nil, errors.New("write not implemented")
	}

	genToken, err := k.Login(ctx, apic)
	require.NoError(t, err, "Login failure")
	require.Equal(t, token, genToken, "Token is incorrect")
}

func TestKubernetesAuthMethodLoginCorrectlyCommunicatesWithAPI(t *testing.T) {
	jwt := "jwt"
	kc := auth.KubernetesConfig{
		Role: "my-role",
		JWTProvider: func() (string, error) {
			return jwt, nil
		},
	}
	k := auth.NewKubernetesMethod(kc)

	ctx := context.Background()

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 72 * time.Hour,
		Renewable:  false,
	}

	apic := FakeAPI{}
	apic.WriteFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathKubernetesLogin {
			// Make behavior assertions in our "fake" because we can't do a real integration test

			require.Empty(t, vaultToken, "Vault token is not empty")
			require.NotEmpty(t, payload, "Payload is empty")

			expectedReqBody := fmt.Sprintf("{\"role\": \"%s\", \"jwt\": \"%s\"}", kc.Role, jwt)
			actualReqBody, _ := json.Marshal(payload)
			require.JSONEq(t, expectedReqBody, string(actualReqBody))

			resBody := fmt.Sprintf(
				"{\"auth\": {\"client_token\": \"%s\", \"lease_duration\": %.0f, \"renewable\": %t}}",
				token.Value,
				token.Expiration.Seconds(),
				token.Renewable)
			res := api.Response{StatusCode: 200, RawBody: io.NopCloser(strings.NewReader(resBody))}
			return &res, nil
		}
		return nil, errors.New("write not implemented")
	}

	genToken, err := k.Login(ctx, apic)
	require.NoError(t, err, "Login failure")
	require.Equal(t, token, genToken, "Token is incorrect")
}

func TestAuthMethodReturnsErrorOnJWTProviderError(t *testing.T) {
	jwtErr := errors.New("uh-oh")
	kc := auth.KubernetesConfig{
		Role: "my-role",
		JWTProvider: func() (string, error) {
			return "", jwtErr
		},
	}
	k := auth.NewKubernetesMethod(kc)

	ctx := context.Background()

	apic := FakeAPI{}

	genToken, err := k.Login(ctx, &apic)
	require.Empty(t, genToken, "Token exists")
	require.ErrorIs(t, err, jwtErr, "Error is incorrect")
}

func TestAuthMethodLoginReturnsErrorOnRequestFailure(t *testing.T) {
	jwt := "jwt"
	kc := auth.KubernetesConfig{
		Role: "my-role",
		JWTProvider: func() (string, error) {
			return jwt, nil
		},
	}
	k := auth.NewKubernetesMethod(kc)

	ctx := context.Background()

	resErr := errors.New("uh-oh")

	apic := FakeAPI{}
	apic.WriteFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathKubernetesLogin {
			return nil, resErr
		}
		return nil, errors.New("write not implemented")
	}

	genToken, err := k.Login(ctx, &apic)
	require.Empty(t, genToken, "Token exists")
	require.ErrorIs(t, err, resErr, "Error is incorrect")
}

func TestAuthMethodLoginReturnsErrorOnInvalidResponseCode(t *testing.T) {
	jwt := "jwt"
	kc := auth.KubernetesConfig{
		Role: "my-role",
		JWTProvider: func() (string, error) {
			return jwt, nil
		},
	}
	k := auth.NewKubernetesMethod(kc)

	ctx := context.Background()

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 72 * time.Hour,
		Renewable:  false,
	}

	apic := FakeAPI{}
	apic.WriteFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathKubernetesLogin {
			resBody := fmt.Sprintf(
				"{\"auth\": {\"client_token\": \"%s\", \"lease_duration\": %.0f, \"renewable\": %t}}",
				token.Value,
				token.Expiration.Seconds(),
				token.Renewable)
			res := api.Response{StatusCode: 418, RawBody: io.NopCloser(strings.NewReader(resBody))}
			return &res, nil
		}
		return nil, errors.New("write not implemented")
	}

	genToken, err := k.Login(ctx, &apic)
	require.Empty(t, genToken, "Token exists")
	require.Error(t, err, "Error does not exist")
	require.Equal(t, err.Error(), "received invalid status code 418 for http request", "Error is incorrect")
}

func TestAuthMethodLoginReturnsErrorOnInvalidJSONResponse(t *testing.T) {
	jwt := "jwt"
	kc := auth.KubernetesConfig{
		Role: "my-role",
		JWTProvider: func() (string, error) {
			return jwt, nil
		},
	}
	k := auth.NewKubernetesMethod(kc)

	ctx := context.Background()

	apic := FakeAPI{}
	apic.WriteFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathKubernetesLogin {
			resBody := "a}"
			res := api.Response{StatusCode: 200, RawBody: io.NopCloser(strings.NewReader(resBody))}
			return &res, nil
		}
		return nil, errors.New("write not implemented")
	}

	genToken, err := k.Login(ctx, &apic)
	require.Empty(t, genToken, "Token exists")
	require.Error(t, err, "Error does not exist")
	require.Equal(t, err.Error(), "invalid character 'a' looking for beginning of value", "Error is incorrect")
}
