package auth_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jaredpetersen/vaultx/api"
	"github.com/jaredpetersen/vaultx/auth"
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

	apic := FakeAPI{}

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 72 * time.Hour,
		Renewable:  true,
	}

	authMethod := FakeMethod{}
	authMethod.loginFunc = func(ctx context.Context, api api.API) (auth.Token, error) {
		return token, nil
	}

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

	apic := FakeAPI{}

	authMethodErr := errors.New("authentication failure")

	authMethod := FakeMethod{}
	authMethod.loginFunc = func(ctx context.Context, api api.API) (auth.Token, error) {
		return auth.Token{Value: "dummy"}, authMethodErr
	}

	ac := auth.Client{
		API:        &apic,
		AuthMethod: &authMethod,
	}

	err := ac.Login(ctx)
	require.ErrorIs(t, err, authMethodErr, "Error is incorrect")

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

	apic := FakeAPI{}
	apic.WriteFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathRenew {
			resBody := fmt.Sprintf(
				"{\"auth\": {\"client_token\": \"%s\", \"lease_duration\": %.0f, \"renewable\": %t}}",
				renewedToken.Value,
				renewedToken.Expiration.Seconds(),
				renewedToken.Renewable)
			res := api.Response{StatusCode: 200, RawBody: io.NopCloser(strings.NewReader(resBody))}
			return &res, nil
		}
		return nil, errors.New("write not implemented")
	}

	ac := auth.Client{API: &apic}

	ac.SetToken(token)
	err := ac.RenewSelf(ctx)
	require.NoError(t, err, "Renew failure")

	storedToken := ac.GetToken()
	require.Equal(t, renewedToken, storedToken, "Token is incorrect")
}

func TestRenewSelfCorrectlyCommunicatesWithAPI(t *testing.T) {
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

	apic := FakeAPI{}
	apic.WriteFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathRenew {
			// Make behavior assertions in our "fake" because we can't do a real integration test

			require.Equal(t, token.Value, vaultToken, "Token is incorrect")
			require.Empty(t, payload, "Payload is not empty")

			resBody := fmt.Sprintf(
				"{\"auth\": {\"client_token\": \"%s\", \"lease_duration\": %.0f, \"renewable\": %t}}",
				renewedToken.Value,
				renewedToken.Expiration.Seconds(),
				renewedToken.Renewable)
			res := api.Response{StatusCode: 200, RawBody: io.NopCloser(strings.NewReader(resBody))}
			return &res, nil
		}
		return nil, errors.New("write not implemented")
	}

	ac := auth.Client{API: &apic}

	ac.SetToken(token)
	err := ac.RenewSelf(ctx)
	require.NoError(t, err, "Renew failure")

	storedToken := ac.GetToken()
	require.Equal(t, renewedToken, storedToken, "Token is incorrect")
}

func TestRenewSelfReturnsErrorOnTokenNotSet(t *testing.T) {
	ctx := context.Background()

	apic := FakeAPI{}

	ac := auth.Client{API: &apic}

	err := ac.RenewSelf(ctx)
	require.Error(t, err, "Error does not exist")
	require.Equal(t, err.Error(), "token must be set first", "Error is incorrect")

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

	apic := FakeAPI{}

	ac := auth.Client{
		API: &apic,
	}

	ac.SetToken(token)
	err := ac.RenewSelf(ctx)
	require.Error(t, err, "Error does not exist")
	require.Equal(t, err.Error(), "token is not renewable", "Error is incorrect")

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

	apic := FakeAPI{}
	apic.WriteFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathRenew {
			return nil, resErr
		}
		return nil, errors.New("write not implemented")
	}

	ac := auth.Client{API: &apic}

	ac.SetToken(token)
	err := ac.RenewSelf(ctx)
	require.ErrorIs(t, err, resErr, "Error is incorrect")

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

	apic := FakeAPI{}
	apic.WriteFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathRenew {
			resBody := fmt.Sprintf(
				"{\"auth\": {\"client_token\": \"%s\", \"lease_duration\": %.0f, \"renewable\": %t}}",
				renewedToken.Value,
				renewedToken.Expiration.Seconds(),
				renewedToken.Renewable)
			res := api.Response{StatusCode: 418, RawBody: io.NopCloser(strings.NewReader(resBody))}
			return &res, nil
		}
		return nil, errors.New("write not implemented")
	}

	ac := auth.Client{API: &apic}

	ac.SetToken(token)
	err := ac.RenewSelf(ctx)
	require.Error(t, err, "Error does not exist")
	require.Equal(t, err.Error(), "received invalid status code 418 for http request", "Error is incorrect")

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

	apic := FakeAPI{}
	apic.WriteFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathRenew {
			res := api.Response{StatusCode: 200, RawBody: io.NopCloser(strings.NewReader("a}"))}
			return &res, nil
		}
		return nil, errors.New("write not implemented")
	}

	ac := auth.Client{API: &apic}

	ac.SetToken(token)
	err := ac.RenewSelf(ctx)
	require.Error(t, err, "Error does not exist")
	require.Equal(t, err.Error(), "failed to map request response: invalid character 'a' looking for beginning of value", "Error is incorrect")

	storedToken := ac.GetToken()
	require.Equal(t, token, storedToken, "Token is incorrect")
}

func TestAutomaticUsesAuthMethodLoginToSetToken(t *testing.T) {
	ctx := context.Background()

	apic := FakeAPI{}

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 1 * time.Hour, // Set long enough in the future so that renew isn't called
		Renewable:  true,
	}

	authMethod := FakeMethod{}
	authMethod.loginFunc = func(ctx context.Context, api api.API) (auth.Token, error) {
		return token, nil
	}

	ac := auth.Client{
		API:        &apic,
		AuthMethod: &authMethod,
	}

	events := ac.Automatic(ctx)

	event := <-events
	storedToken := ac.GetToken()
	require.Equal(t, auth.Event{Type: "login"}, event, "Unexpected event")
	require.Equal(t, token, storedToken, "Token is incorrect")
}

func TestAutomaticHandlesAuthMethodLoginError(t *testing.T) {
	ctx := context.Background()

	apic := FakeAPI{}

	loginErr := errors.New("uh-oh")

	authMethod := FakeMethod{}
	authMethod.loginFunc = func(ctx context.Context, api api.API) (auth.Token, error) {
		return auth.Token{}, loginErr
	}

	ac := auth.Client{
		API:        &apic,
		AuthMethod: &authMethod,
	}

	events := ac.Automatic(ctx)

	for i := 0; i < 3; i++ {
		event := <-events
		storedToken := ac.GetToken()
		require.Equal(t, "login", event.Type, "Event type is incorrect")
		require.ErrorIs(t, event.Err, loginErr, "Event error is incorrect")
		require.Empty(t, storedToken, "Token is not empty")
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

	apic := FakeAPI{}
	apic.WriteFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathRenew {
			resBody := fmt.Sprintf(
				"{\"auth\": {\"client_token\": \"%s\", \"lease_duration\": %.0f, \"renewable\": %t}}",
				renewedToken.Value,
				renewedToken.Expiration.Seconds(),
				renewedToken.Renewable)
			res := api.Response{StatusCode: 200, RawBody: io.NopCloser(strings.NewReader(resBody))}
			return &res, nil
		}
		return nil, errors.New("write not implemented")
	}

	authMethod := FakeMethod{}
	authMethod.loginFunc = func(ctx context.Context, api api.API) (auth.Token, error) {
		return token, nil
	}

	ac := auth.Client{
		API:        &apic,
		AuthMethod: &authMethod,
	}

	events := ac.Automatic(ctx)

	// First event is a login
	event := <-events
	storedToken := ac.GetToken()
	require.Equal(t, auth.Event{Type: "login"}, event, "Unexpected event")
	require.Equal(t, token, storedToken, "Token is incorrect")

	// Subsequent event is a renewal
	event = <-events
	storedToken = ac.GetToken()
	require.Equal(t, auth.Event{Type: "renew"}, event, "Unexpected event")
	require.Equal(t, renewedToken, storedToken, "Token is incorrect")
}

func TestAutomaticHandlesRenewError(t *testing.T) {
	ctx := context.Background()

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 6 * time.Second, // Set low enough to renew
		Renewable:  true,
	}

	renewErr := errors.New("uh-oh")

	apic := FakeAPI{}
	apic.WriteFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathRenew {
			return nil, renewErr
		}
		return nil, errors.New("write not implemented")
	}

	authMethod := FakeMethod{}
	authMethod.loginFunc = func(ctx context.Context, api api.API) (auth.Token, error) {
		return token, nil
	}

	ac := auth.Client{
		API:        &apic,
		AuthMethod: &authMethod,
	}

	events := ac.Automatic(ctx)

	// First event is a login
	loginEvent := <-events
	storedToken := ac.GetToken()
	require.Equal(t, auth.Event{Type: "login"}, loginEvent, "Unexpected loginEvent")
	require.Equal(t, token, storedToken, "Token is incorrect")

	// Subsequent renewals fail
	for i := 0; i < 3; i++ {
		renewTokenEvent := <-events
		storedToken = ac.GetToken()
		require.Equal(t, "renew", renewTokenEvent.Type, "Event type is incorrect")
		require.ErrorIs(t, renewTokenEvent.Err, renewErr, "Event error is incorrect")

		// Token is not updated
		require.Equal(t, token, storedToken, "Token is incorrect")
	}
}

func TestAutomaticRenewsTokenOnTime(t *testing.T) {
	ctx := context.Background()

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 6 * time.Second, // Set low enough to renew
		Renewable:  true,
	}

	apic := FakeAPI{}
	apic.WriteFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathRenew {
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

	authMethod := FakeMethod{}
	authMethod.loginFunc = func(ctx context.Context, api api.API) (auth.Token, error) {
		return token, nil
	}

	ac := auth.Client{
		API:        &apic,
		AuthMethod: &authMethod,
	}

	events := ac.Automatic(ctx)

	// First event is a login
	event := <-events
	storedToken := ac.GetToken()
	require.Equal(t, auth.Event{Type: "login"}, event, "Unexpected event")
	require.Equal(t, token, storedToken, "Token is incorrect")

	// Subsequent events are renewals
	for i := 0; i < 3; i++ {
		start := time.Now()

		event = <-events
		storedToken = ac.GetToken()
		require.Equal(t, auth.Event{Type: "renew"}, event, "Unexpected event")
		require.Equal(t, token, storedToken, "Token is incorrect")

		end := time.Now()
		duration := end.Sub(start)

		// Renewal is 5 seconds before expiration, so an expiration of 5 seconds means a renewal every 1 second
		// Time scheduling isn't exact, so allow some variability
		require.Greater(t, duration, 500*time.Millisecond, "Renewal took too long")
		require.Less(t, duration, 1500*time.Millisecond, "Renewal was too fast")
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

	apic := FakeAPI{}
	apic.WriteFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathRenew {
			resBody := fmt.Sprintf(
				"{\"auth\": {\"client_token\": \"%s\", \"lease_duration\": %.0f, \"renewable\": %t}}",
				renewedToken.Value,
				renewedToken.Expiration.Seconds(),
				renewedToken.Renewable)
			res := api.Response{StatusCode: 200, RawBody: io.NopCloser(strings.NewReader(resBody))}
			return &res, nil
		}
		return nil, errors.New("write not implemented")
	}

	authMethod := FakeMethod{}
	authMethod.loginFunc = func(ctx context.Context, api api.API) (auth.Token, error) {
		return token, nil
	}

	ac := auth.Client{
		API:        &apic,
		AuthMethod: &authMethod,
	}

	events := ac.Automatic(ctx)

	// First event is a login
	event := <-events
	storedToken := ac.GetToken()
	require.Equal(t, auth.Event{Type: "login"}, event, "Unexpected event")
	require.Equal(t, token, storedToken, "Token is incorrect")

	// Subsequent event is a renewal
	event = <-events
	storedToken = ac.GetToken()
	require.Equal(t, auth.Event{Type: "renew"}, event, "Unexpected event")
	require.Equal(t, renewedToken, storedToken, "Token is incorrect")

	// Subsequent event is a login since the renewed token cannot be renewed again
	event = <-events
	storedToken = ac.GetToken()
	require.Equal(t, auth.Event{Type: "login"}, event, "Unexpected event")
	require.Equal(t, token, storedToken, "Token is incorrect")
}

func TestAutomaticStopsAfterContextDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	token := auth.Token{
		Value:      "sometoken",
		Expiration: 1 * time.Hour, // Set long enough in the future so that renew isn't called
		Renewable:  true,
	}

	apic := FakeAPI{}
	apic.WriteFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathRenew {
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

	authMethod := FakeMethod{}
	authMethod.loginFunc = func(ctx context.Context, api api.API) (auth.Token, error) {
		return token, nil
	}

	ac := auth.Client{
		API:        &apic,
		AuthMethod: &authMethod,
	}

	events := ac.Automatic(ctx)

	event := <-events
	storedToken := ac.GetToken()
	require.Equal(t, auth.Event{Type: "login"}, event, "Unexpected event")
	require.Equal(t, token, storedToken, "Token is incorrect")

	// Stop auth activity
	cancel()

	// Receive any events remaining
	receiveCount := 0
	eventsChanOpen := true
	for eventsChanOpen {
		event, ok := <-events
		if ok {
			receiveCount++
			require.Equal(t, auth.Event{Type: "renew"}, event, "Unexpected event")
			require.Equal(t, token, storedToken, "Token is incorrect")
		} else {
			eventsChanOpen = false
		}
	}

	require.Equal(t, receiveCount, 0, "Too many events generated")
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

	apic := FakeAPI{}
	apic.WriteFunc = func(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
		if path == apiPathRenew {
			resBody := fmt.Sprintf(
				"{\"auth\": {\"client_token\": \"%s\", \"lease_duration\": %.0f, \"renewable\": %t}}",
				renewedToken.Value,
				renewedToken.Expiration.Seconds(),
				renewedToken.Renewable)
			res := api.Response{StatusCode: 200, RawBody: io.NopCloser(strings.NewReader(resBody))}
			return &res, nil
		}
		return nil, errors.New("write not implemented")
	}

	authMethod := FakeMethod{}
	authMethod.loginFunc = func(ctx context.Context, api api.API) (auth.Token, error) {
		return token, nil
	}

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
	require.Equal(t, renewedToken, storedToken)
}
