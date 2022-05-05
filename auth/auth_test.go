package auth_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jaredpetersen/vaultx/api"
	"github.com/jaredpetersen/vaultx/auth"
	authmocks "github.com/jaredpetersen/vaultx/auth/mocks"
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

	apic := fakeAPI{}

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 72 * time.Hour,
		Renewable:  true,
	}

	authMethod := authmocks.Method{}
	authMethod.On("Login", ctx, &apic).Return(token, nil)

	ac := auth.Client{
		API:        &apic,
		AuthMethod: &authMethod,
	}

	err := ac.Login(ctx)
	require.NoError(t, err, "Login failure")

	storedToken := ac.GetToken()
	require.Equal(t, token, storedToken, "Token is incorrect")
}

func TestLoginReturnsErrorOnAuthMethodError(t *testing.T) {
	ctx := context.Background()

	apic := fakeAPI{}

	authMethodErr := errors.New("authentication failure")

	authMethod := authmocks.Method{}
	authMethod.On("Login", ctx, &apic).Return(auth.Token{Value: "dummy"}, authMethodErr)

	ac := auth.Client{
		API:        &apic,
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

	apic := fakeAPI{}
	apic.writeFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == "/v1/auth/token/renew-self" && vaultToken == token.Value && payload == nil {
			resBody := fmt.Sprintf(
				"{\"auth\": {\"client_token\": \"%s\", \"lease_duration\": %.0f, \"renewable\": %t}}",
				renewedToken.Value,
				renewedToken.Expiration.Seconds(),
				renewedToken.Renewable)
			res := api.Response{StatusCode: 200, RawBody: io.NopCloser(strings.NewReader(resBody))}
			return &res, nil
		}
		return nil, nil
	}

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

	apic := fakeAPI{}

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

	apic := fakeAPI{}

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

	apic := fakeAPI{}
	apic.writeFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		return nil, resErr
	}

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

	apic := fakeAPI{}
	apic.writeFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathRenew && vaultToken == token.Value {
			resBody := fmt.Sprintf(
				"{\"auth\": {\"client_token\": \"%s\", \"lease_duration\": %.0f, \"renewable\": %t}}",
				renewedToken.Value,
				renewedToken.Expiration.Seconds(),
				renewedToken.Renewable)
			res := api.Response{StatusCode: 418, RawBody: io.NopCloser(strings.NewReader(resBody))}
			return &res, nil
		}
		return nil, nil
	}

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

	apic := fakeAPI{}
	apic.writeFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathRenew && vaultToken == token.Value {
			res := api.Response{StatusCode: 200, RawBody: io.NopCloser(strings.NewReader("a}"))}
			return &res, nil
		}
		return nil, nil
	}

	ac := auth.Client{
		API: &apic,
	}

	ac.SetToken(token)
	err := ac.RenewSelf(ctx)
	require.Error(t, err, "Error does not exist")

	storedToken := ac.GetToken()
	require.Equal(t, token, storedToken, "Token is incorrect")
}

func TestAutomaticUsesAuthMethodLoginToSetToken(t *testing.T) {
	ctx := context.Background()

	apic := fakeAPI{}

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 1 * time.Hour, // Set long enough in the future so that renew isn't called
		Renewable:  true,
	}

	authMethod := authmocks.Method{}
	authMethod.On("Login", ctx, &apic).Return(token, nil)

	ac := auth.Client{
		API:        &apic,
		AuthMethod: &authMethod,
	}

	events := ac.Automatic(ctx)

	event := <-events
	storedToken := ac.GetToken()
	assert.Equal(t, auth.Event{Type: "login"}, event, "Unexpected event")
	assert.Equal(t, token, storedToken, "Token is incorrect")
}

func TestAutomaticHandlesAuthMethodLoginError(t *testing.T) {
	ctx := context.Background()

	apic := fakeAPI{}

	loginErr := errors.New("uh-oh")

	authMethod := authmocks.Method{}
	authMethod.On("Login", ctx, &apic).Return(auth.Token{}, loginErr)

	ac := auth.Client{
		API:        &apic,
		AuthMethod: &authMethod,
	}

	events := ac.Automatic(ctx)

	for i := 0; i < 3; i++ {
		event := <-events
		storedToken := ac.GetToken()
		assert.Equal(t, "login", event.Type, "Incorrect event type")
		assert.ErrorIs(t, event.Err, loginErr, "Incorrect event error")
		assert.Empty(t, storedToken, "Token is not empty")
	}
}

func TestAutomaticRenewsTokenAndSetsToken(t *testing.T) {
	ctx := context.Background()

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 6 * time.Second, // Set low enough to renew
		Renewable:  true,
	}
	renewedToken := auth.Token{
		Value:      "renewedtoken",
		Expiration: 8 * time.Second,
		Renewable:  false,
	}

	apic := fakeAPI{}
	apic.writeFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathRenew && vaultToken == token.Value {
			resBody := fmt.Sprintf(
				"{\"auth\": {\"client_token\": \"%s\", \"lease_duration\": %.0f, \"renewable\": %t}}",
				renewedToken.Value,
				renewedToken.Expiration.Seconds(),
				renewedToken.Renewable)
			res := api.Response{StatusCode: 200, RawBody: io.NopCloser(strings.NewReader(resBody))}
			return &res, nil
		}
		return nil, nil
	}

	authMethod := authmocks.Method{}
	authMethod.On("Login", ctx, &apic).Return(token, nil)

	ac := auth.Client{
		API:        &apic,
		AuthMethod: &authMethod,
	}

	events := ac.Automatic(ctx)

	// First event is a login
	event := <-events
	storedToken := ac.GetToken()
	assert.Equal(t, auth.Event{Type: "login"}, event, "Unexpected event")
	assert.Equal(t, token, storedToken, "Token is incorrect")

	// Subsequent event is a renewal
	event = <-events
	storedToken = ac.GetToken()
	assert.Equal(t, auth.Event{Type: "renew"}, event, "Unexpected event")
	assert.Equal(t, renewedToken, storedToken, "Token is incorrect")
}

func TestAutomaticHandlesRenewError(t *testing.T) {
	ctx := context.Background()

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 6 * time.Second, // Set low enough to renew
		Renewable:  true,
	}

	renewErr := errors.New("uh-oh")

	apic := fakeAPI{}
	apic.writeFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		return nil, renewErr
	}

	authMethod := authmocks.Method{}
	authMethod.On("Login", ctx, &apic).Return(token, nil)

	ac := auth.Client{
		API:        &apic,
		AuthMethod: &authMethod,
	}

	events := ac.Automatic(ctx)

	// First event is a login
	event := <-events
	storedToken := ac.GetToken()
	assert.Equal(t, auth.Event{Type: "login"}, event, "Unexpected event")
	assert.Equal(t, token, storedToken, "Token is incorrect")

	// Subsequent renewals fail
	for i := 0; i < 3; i++ {
		renewToken := <-events
		storedToken = ac.GetToken()
		assert.Equal(t, "renew", renewToken.Type, "Incorrect renewToken type")
		assert.ErrorIs(t, renewToken.Err, renewErr, "Incorrect renewToken error")

		// Token is not updated
		assert.Equal(t, token, storedToken, "Token is incorrect")
	}
}

func TestAutomaticRenewsTokenOnTime(t *testing.T) {
	ctx := context.Background()

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 6 * time.Second, // Set low enough to renew
		Renewable:  true,
	}

	apic := fakeAPI{}
	apic.writeFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathRenew && vaultToken == token.Value {
			resBody := fmt.Sprintf(
				"{\"auth\": {\"client_token\": \"%s\", \"lease_duration\": %.0f, \"renewable\": %t}}",
				token.Value,
				token.Expiration.Seconds(),
				token.Renewable)
			res := api.Response{StatusCode: 200, RawBody: io.NopCloser(strings.NewReader(resBody))}
			return &res, nil
		}
		return nil, nil
	}

	authMethod := authmocks.Method{}
	authMethod.On("Login", ctx, &apic).Return(token, nil)

	ac := auth.Client{
		API:        &apic,
		AuthMethod: &authMethod,
	}

	events := ac.Automatic(ctx)

	// First event is a login
	event := <-events
	storedToken := ac.GetToken()
	assert.Equal(t, auth.Event{Type: "login"}, event, "Unexpected event")
	assert.Equal(t, token, storedToken, "Token is incorrect")

	// Subsequent events are renewals
	for i := 0; i < 3; i++ {
		start := time.Now()

		event = <-events
		storedToken = ac.GetToken()
		assert.Equal(t, auth.Event{Type: "renew"}, event, "Unexpected event")
		assert.Equal(t, token, storedToken, "Token is incorrect")

		end := time.Now()
		duration := end.Sub(start)

		// Renewal is 5 seconds before expiration, so an expiration of 5 seconds means a renewal every 1 second
		// Time scheduling isn't exact, so allow some variability
		assert.Greater(t, duration, 500*time.Millisecond, "Renewal took too long")
		assert.Less(t, duration, 1500*time.Millisecond, "Renewal was too fast")
	}
}

func TestAutomaticDoesNotRenewNonRenewableToken(t *testing.T) {
	ctx := context.Background()

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 6 * time.Second, // Set low enough to renew
		Renewable:  true,
	}
	renewedToken := auth.Token{
		Value:      "renewedtoken",
		Expiration: 8 * time.Second,
		Renewable:  false,
	}

	apic := fakeAPI{}
	apic.writeFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathRenew && vaultToken == token.Value {
			resBody := fmt.Sprintf(
				"{\"auth\": {\"client_token\": \"%s\", \"lease_duration\": %.0f, \"renewable\": %t}}",
				renewedToken.Value,
				renewedToken.Expiration.Seconds(),
				renewedToken.Renewable)
			res := api.Response{StatusCode: 200, RawBody: io.NopCloser(strings.NewReader(resBody))}
			return &res, nil
		}
		return nil, nil
	}

	authMethod := authmocks.Method{}
	authMethod.On("Login", ctx, &apic).Return(token, nil)

	ac := auth.Client{
		API:        &apic,
		AuthMethod: &authMethod,
	}

	events := ac.Automatic(ctx)

	// First event is a login
	event := <-events
	storedToken := ac.GetToken()
	assert.Equal(t, auth.Event{Type: "login"}, event, "Unexpected event")
	assert.Equal(t, token, storedToken, "Token is incorrect")

	// Subsequent event is a renewal
	event = <-events
	storedToken = ac.GetToken()
	assert.Equal(t, auth.Event{Type: "renew"}, event, "Unexpected event")
	assert.Equal(t, renewedToken, storedToken, "Token is incorrect")

	// Subsequent event is a login since the renewed token cannot be renewed again
	event = <-events
	storedToken = ac.GetToken()
	assert.Equal(t, auth.Event{Type: "login"}, event, "Unexpected event")
	assert.Equal(t, token, storedToken, "Token is incorrect")
}

func TestAutomaticStopsAfterContextDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 1 * time.Hour, // Set long enough in the future so that renew isn't called
		Renewable:  true,
	}

	apic := fakeAPI{}
	apic.writeFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathRenew && vaultToken == token.Value {
			resBody := fmt.Sprintf(
				"{\"auth\": {\"client_token\": \"%s\", \"lease_duration\": %.0f, \"renewable\": %t}}",
				token.Value,
				token.Expiration.Seconds(),
				token.Renewable)
			res := api.Response{StatusCode: 200, RawBody: io.NopCloser(strings.NewReader(resBody))}
			return &res, nil
		}
		return nil, nil
	}

	authMethod := authmocks.Method{}
	authMethod.On("Login", ctx, &apic).Return(token, nil)

	ac := auth.Client{
		API:        &apic,
		AuthMethod: &authMethod,
	}

	events := ac.Automatic(ctx)

	event := <-events
	storedToken := ac.GetToken()
	assert.Equal(t, auth.Event{Type: "login"}, event, "Unexpected event")
	assert.Equal(t, token, storedToken, "Token is incorrect")

	// Stop auth activity
	cancel()

	// Receive any events remaining
	receiveCount := 0
	eventsChanOpen := true
	for eventsChanOpen {
		event, ok := <-events
		if ok {
			receiveCount++
			assert.Equal(t, auth.Event{Type: "renew"}, event, "Unexpected event")
			assert.Equal(t, token, storedToken, "Token is incorrect")
		} else {
			eventsChanOpen = false
		}
	}

	assert.Equal(t, receiveCount, 0, "Too many events generated")
}

func TestAutomaticRenewsTokenDespiteNotReceivingEvents(t *testing.T) {
	ctx := context.Background()

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 6 * time.Second, // Set low enough to renew
		Renewable:  true,
	}
	renewedToken := auth.Token{
		Value:      "renewedtoken",
		Expiration: 8 * time.Second,
		Renewable:  false,
	}

	apic := fakeAPI{}
	apic.writeFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathRenew && vaultToken == token.Value {
			resBody := fmt.Sprintf(
				"{\"auth\": {\"client_token\": \"%s\", \"lease_duration\": %.0f, \"renewable\": %t}}",
				renewedToken.Value,
				renewedToken.Expiration.Seconds(),
				renewedToken.Renewable)
			res := api.Response{StatusCode: 200, RawBody: io.NopCloser(strings.NewReader(resBody))}
			return &res, nil
		}
		return nil, nil
	}

	authMethod := authmocks.Method{}
	authMethod.On("Login", ctx, &apic).Return(token, nil)

	ac := auth.Client{
		API:        &apic,
		AuthMethod: &authMethod,
	}

	ac.Automatic(ctx)

	// Wait enough time for a login and renew event to take place
	// Don't actually receive any events produced by Automatic -- we want to confirm that we can still do work even
	// if the channel is ignored
	time.Sleep(time.Second * 2)

	storedToken := ac.GetToken()
	assert.Equal(t, renewedToken, storedToken)
}
