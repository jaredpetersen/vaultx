package k8s_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/jaredpetersen/vaultx/api"
	apimocks "github.com/jaredpetersen/vaultx/api/mocks"
	"github.com/jaredpetersen/vaultx/auth"
	"github.com/jaredpetersen/vaultx/auth/k8s"
)

func TestNewProvidesDefaultJWTProvider(t *testing.T) {
	kc := k8s.Config{Role: "my-role"}
	k := k8s.New(kc)

	require.NotEmpty(t, k.Config.JWTProvider, "JWT provider is empty")

	// Can't assert that k.Config.JWTProvider is set to auth.DefaultJWTProvider
}

func TestAuthMethodLoginGeneratesToken(t *testing.T) {
	jwt := "jwt"
	kc := k8s.Config{
		Role: "my-role",
		JWTProvider: func() (string, error) {
			return jwt, nil
		},
	}
	k := k8s.New(kc)

	ctx := context.Background()

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 72 * time.Hour,
		Renewable:  false,
	}

	resBody := fmt.Sprintf(
		"{\"auth\": {\"client_token\": \"%s\", \"lease_duration\": %.0f, \"renewable\": %t}}",
		token.Value,
		token.Expiration.Seconds(),
		token.Renewable)
	res := api.Response{StatusCode: 200, RawBody: io.NopCloser(strings.NewReader(resBody))}

	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/auth/kubernetes/login", "", mock.MatchedBy(func(input interface{}) bool {
		expectedReqBody := fmt.Sprintf("{\"role\": \"%s\", \"jwt\": \"%s\"}", kc.Role, jwt)
		actualReqBody, _ := json.Marshal(input)
		return assert.JSONEq(t, expectedReqBody, string(actualReqBody))
	})).Return(&res, nil)

	genToken, err := k.Login(ctx, &apic)
	assert.NoError(t, err, "Login failure")
	assert.Equal(t, token, genToken, "Token is incorrect")
}

func TestAuthMethodReturnsErrorOnJWTProviderError(t *testing.T) {
	jwtErr := errors.New("uh-oh")
	kc := k8s.Config{
		Role: "my-role",
		JWTProvider: func() (string, error) {
			return "", jwtErr
		},
	}
	k := k8s.New(kc)

	ctx := context.Background()

	apic := apimocks.API{}

	genToken, err := k.Login(ctx, &apic)
	assert.Empty(t, genToken, "Token exists")
	assert.ErrorIs(t, err, jwtErr, "Incorrect error")
}

func TestAuthMethodLoginReturnsErrorOnRequestFailure(t *testing.T) {
	jwt := "jwt"
	kc := k8s.Config{
		Role: "my-role",
		JWTProvider: func() (string, error) {
			return jwt, nil
		},
	}
	k := k8s.New(kc)

	ctx := context.Background()

	resErr := errors.New("uh-oh")

	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/auth/kubernetes/login", "", mock.Anything).Return(nil, resErr)

	genToken, err := k.Login(ctx, &apic)
	assert.Empty(t, genToken, "Token exists")
	assert.ErrorIs(t, err, resErr, "Incorrect error")
}

func TestAuthMethodLoginReturnsErrorOnInvalidResponseCode(t *testing.T) {
	jwt := "jwt"
	kc := k8s.Config{
		Role: "my-role",
		JWTProvider: func() (string, error) {
			return jwt, nil
		},
	}
	k := k8s.New(kc)

	ctx := context.Background()

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 72 * time.Hour,
		Renewable:  false,
	}

	resBody := fmt.Sprintf(
		"{\"auth\": {\"client_token\": \"%s\", \"lease_duration\": %.0f, \"renewable\": %t}}",
		token.Value,
		token.Expiration.Seconds(),
		token.Renewable)
	res := api.Response{StatusCode: 418, RawBody: io.NopCloser(strings.NewReader(resBody))}

	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/auth/kubernetes/login", "", mock.Anything).Return(&res, nil)

	genToken, err := k.Login(ctx, &apic)
	assert.Empty(t, genToken, "Token exists")
	assert.Error(t, err, "Error does not exist")
	assert.Errorf(t, err, "received invalid status code 418 for http request")
}

func TestAuthMethodLoginReturnsErrorOnInvalidJSONResponse(t *testing.T) {
	jwt := "jwt"
	kc := k8s.Config{
		Role: "my-role",
		JWTProvider: func() (string, error) {
			return jwt, nil
		},
	}
	k := k8s.New(kc)

	ctx := context.Background()

	resBody := "a}"
	res := api.Response{StatusCode: 200, RawBody: io.NopCloser(strings.NewReader(resBody))}

	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/auth/kubernetes/login", "", mock.Anything).Return(&res, nil)

	genToken, err := k.Login(ctx, &apic)
	assert.Empty(t, genToken, "Token exists")
	assert.Error(t, err, "Error does not exist")
}
