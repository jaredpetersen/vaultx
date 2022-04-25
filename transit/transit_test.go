package transit_test

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
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/jaredpetersen/vaultx/api"
	apimocks "github.com/jaredpetersen/vaultx/api/mocks"
	"github.com/jaredpetersen/vaultx/auth"
	authmocks "github.com/jaredpetersen/vaultx/auth/mocks"
	"github.com/jaredpetersen/vaultx/transit"

	"github.com/jaredpetersen/vaultx/internal/testcontainervault"
)

func TestEncryptEncryptsData(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		ClientToken: "vault token",
	}
	tokenManager := authmocks.TokenManager{}
	tokenManager.On("GetToken").Return(&token, nil)

	// Set up mocked API response
	resBody := "{\"data\": {\"ciphertext\": \"vault:v1:asdfasdfasdf\"}}"
	res := api.Response{
		StatusCode: 200,
		RawBody:    io.NopCloser(strings.NewReader(resBody)),
	}

	transitKey := "my-key"

	// Set up mock API
	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/transit/encrypt/"+transitKey, token.ClientToken, mock.MatchedBy(func(input interface{}) bool {
		actualReqBody, _ := json.Marshal(input)
		return assert.JSONEq(t, "{\"plaintext\": \"dGhpcyBpcyBteSBzZWNyZXQ=\"}", string(actualReqBody))
	})).Return(&res, nil)

	transitc := transit.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	encrypted, err := transitc.Encrypt(ctx, transitKey, []byte("this is my secret"))
	require.NoError(t, err, "Encryption failure")
	require.NotEmpty(t, encrypted, "Encrypted value is empty")
	require.True(t, strings.HasPrefix(encrypted, "vault:v1:"))
}

func TestEncryptReturnsErrorOnRequestFailure(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		ClientToken: "vault token",
	}
	tokenManager := authmocks.TokenManager{}
	tokenManager.On("GetToken").Return(&token, nil)

	// Set up mocked API request error
	resErr := errors.New("failed request")

	transitKey := "my-key"

	// Set up mock API
	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/transit/encrypt/"+transitKey, token.ClientToken, mock.Anything).Return(nil, resErr)

	transitc := transit.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}
	encrypted, err := transitc.Encrypt(ctx, transitKey, []byte("this is my secret"))
	require.Error(t, err, "Error does not exist")
	require.ErrorIs(t, err, resErr, "Error is incorrect")
	require.Empty(t, encrypted, "Encrypted value is not empty")
}

func TestEncryptReturnsErrorOnInvalidResponseCode(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		ClientToken: "vault token",
	}
	tokenManager := authmocks.TokenManager{}
	tokenManager.On("GetToken").Return(&token, nil)

	// Set up mocked API response with valid body but incorrect status code
	resBody := "{\"data\": {\"ciphertext\": \"vault:v1:asdfasdfasdf\"}}"
	res := api.Response{
		StatusCode: 418,
		RawBody:    io.NopCloser(strings.NewReader(resBody)),
	}

	transitKey := "my-key"

	// Set up mock API
	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/transit/encrypt/"+transitKey, token.ClientToken, mock.Anything).Return(&res, nil)

	transitc := transit.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}
	encrypted, err := transitc.Encrypt(ctx, transitKey, []byte("this is my secret"))
	require.Error(t, err, "Error does not exist")
	require.Errorf(t, err, "received invalid status code 418 for http request")
	require.Empty(t, encrypted, "Encrypted value is not empty")
}

func TestEncryptReturnsErrorOnInvalidJSONResponse(t *testing.T) {
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

	transitKey := "my-key"

	// Set up mock API
	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/transit/encrypt/"+transitKey, token.ClientToken, mock.Anything).Return(&res, nil)

	transitc := transit.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}
	encrypted, err := transitc.Encrypt(ctx, transitKey, []byte("this is my secret"))
	require.Error(t, err, "Error does not exist")
	require.Empty(t, encrypted, "Encrypted value is not empty")
}

func TestIntegrationEncryptEncryptsData(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	vaultContainer, err := testcontainervault.NewContainer(ctx)
	require.NoError(t, err, "Failed to set up Vault container")
	defer vaultContainer.Terminate(ctx)

	err = vaultContainer.EnableTransit(ctx)
	require.NoError(t, err, "Failed to initialize Vault container")

	transitKey := "my-key"
	err = vaultContainer.CreateTransitKey(ctx, transitKey)
	require.NoError(t, err, "Failed to create Vault transit key")

	apic := api.Client{
		HTTP: cleanhttp.DefaultClient(),
		URL:  vaultContainer.URI,
	}

	authc := auth.Client{
		API: &apic,
	}
	authc.SetToken(&auth.Token{ClientToken: vaultContainer.Token})

	transitc := transit.Client{
		API:          &apic,
		TokenManager: &authc,
	}

	plaintext := "this is my secret"
	encrypted, err := transitc.Encrypt(ctx, transitKey, []byte(plaintext))
	require.NoError(t, err, "Encryption failure")
	require.NotEmpty(t, encrypted, "Encrypted value is empty")
	require.True(t, strings.HasPrefix(encrypted, "vault:v1:"))
}

func TestEncryptBatchEncryptsData(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		ClientToken: "vault token",
	}
	tokenManager := authmocks.TokenManager{}
	tokenManager.On("GetToken").Return(&token, nil)

	// Set up mocked API response
	secretA := "this is my secret"
	secretAEncrypted := "vault:v1:asdfasdfasdf"
	secretB := "this is another secret"
	secretBEncrypted := "vault:v1:qwertyqwerty"
	secretC := "this is yet another secret"
	secretCEncrypted := "vault:v1:zxcvbnzxcvbn"

	resBody := fmt.Sprintf(`{
		"data": {
			"batch_results": [
				{"ciphertext": "%s"},
				{"ciphertext": "%s"},
				{"ciphertext": "%s"}
			]
		}
	}`, secretAEncrypted, secretBEncrypted, secretCEncrypted)
	res := api.Response{
		StatusCode: 200,
		RawBody:    io.NopCloser(strings.NewReader(resBody)),
	}

	transitKey := "my-key"

	// Set up mock API
	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/transit/encrypt/"+transitKey, token.ClientToken, mock.MatchedBy(func(input interface{}) bool {
		actualReqBody, _ := json.Marshal(input)
		expectedReqBody := `{
			"batch_input": [
				{"plaintext": "dGhpcyBpcyBteSBzZWNyZXQ="},
				{"plaintext": "dGhpcyBpcyBhbm90aGVyIHNlY3JldA=="},
				{"plaintext": "dGhpcyBpcyB5ZXQgYW5vdGhlciBzZWNyZXQ="}
			]
		}`
		return assert.JSONEq(t, expectedReqBody, string(actualReqBody))
	})).Return(&res, nil)

	transitc := transit.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	encryptedBatch, err := transitc.EncryptBatch(ctx, transitKey, []byte(secretA), []byte(secretB), []byte(secretC))
	require.NoError(t, err, "Encryption failure")
	require.NotEmpty(t, encryptedBatch, "Encrypted batch is empty")
	require.Equal(t, 3, len(encryptedBatch), "Incorrect number of encrypted items")
	require.Equal(t, secretAEncrypted, encryptedBatch[0])
	require.Equal(t, secretBEncrypted, encryptedBatch[1])
	require.Equal(t, secretCEncrypted, encryptedBatch[2])
}

func TestEncryptBatchReturnsErrorOnRequestFailure(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		ClientToken: "vault token",
	}
	tokenManager := authmocks.TokenManager{}
	tokenManager.On("GetToken").Return(&token, nil)

	// Set up mocked API request error
	resErr := errors.New("failed request")

	transitKey := "my-key"

	// Set up mock API
	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/transit/encrypt/"+transitKey, token.ClientToken, mock.Anything).Return(nil, resErr)

	transitc := transit.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	secretA := "this is my secret"
	secretB := "this is another secret"
	secretC := "this is yet another secret"

	encryptedBatch, err := transitc.EncryptBatch(ctx, transitKey, []byte(secretA), []byte(secretB), []byte(secretC))
	require.Error(t, err, "Error does not exist")
	require.ErrorIs(t, err, resErr, "Error is incorrect")
	require.Empty(t, encryptedBatch, "Encrypted batch is not empty")
}

func TestEncryptBatchReturnsErrorOnInvalidResponseCode(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		ClientToken: "vault token",
	}
	tokenManager := authmocks.TokenManager{}
	tokenManager.On("GetToken").Return(&token, nil)

	// Set up mocked API response with valid body but incorrect status code
	resBody := `{
		"data": {
			"batch_results": [
				{"ciphertext": "vault:v1:asdfasdfasdf"},
				{"ciphertext": "vault:v1:qwertyqwerty"},
				{"ciphertext": "vault:v1:zxcvbnzxcvbn"}
			]
		}
	}`
	res := api.Response{
		StatusCode: 418,
		RawBody:    io.NopCloser(strings.NewReader(resBody)),
	}

	transitKey := "my-key"

	// Set up mock API
	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/transit/encrypt/"+transitKey, token.ClientToken, mock.Anything).Return(&res, nil)

	transitc := transit.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	secretA := "this is my secret"
	secretB := "this is another secret"
	secretC := "this is yet another secret"

	encryptedBatch, err := transitc.EncryptBatch(ctx, transitKey, []byte(secretA), []byte(secretB), []byte(secretC))
	require.Error(t, err, "Error does not exist")
	require.Errorf(t, err, "received invalid status code 418 for http request")
	require.Empty(t, encryptedBatch, "Encrypted batch is not empty")
}

func TestEncryptBatchReturnsErrorOnInvalidJSONResponse(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		ClientToken: "vault token",
	}
	tokenManager := authmocks.TokenManager{}
	tokenManager.On("GetToken").Return(&token, nil)

	// Set up mocked API response with valid body but incorrect status code
	resBody := "a}"
	res := api.Response{
		StatusCode: 200,
		RawBody:    io.NopCloser(strings.NewReader(resBody)),
	}

	transitKey := "my-key"

	// Set up mock API
	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/transit/encrypt/"+transitKey, token.ClientToken, mock.Anything).Return(&res, nil)

	transitc := transit.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	secretA := "this is my secret"
	secretB := "this is another secret"
	secretC := "this is yet another secret"

	encryptedBatch, err := transitc.EncryptBatch(ctx, transitKey, []byte(secretA), []byte(secretB), []byte(secretC))
	require.Error(t, err, "Error does not exist")
	require.Empty(t, encryptedBatch, "Encrypted batch is not empty")
}

func TestIntegrationEncryptBatchEncryptsData(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	vaultContainer, err := testcontainervault.NewContainer(ctx)
	require.NoError(t, err, "Failed to set up Vault container")
	defer vaultContainer.Terminate(ctx)

	err = vaultContainer.EnableTransit(ctx)
	require.NoError(t, err, "Failed to initialize Vault container")

	transitKey := "my-key"
	err = vaultContainer.CreateTransitKey(ctx, transitKey)
	require.NoError(t, err, "Failed to create Vault transit key")

	apic := api.Client{
		HTTP: cleanhttp.DefaultClient(),
		URL:  vaultContainer.URI,
	}

	authc := auth.Client{
		API: &apic,
	}
	authc.SetToken(&auth.Token{ClientToken: vaultContainer.Token})

	transitc := transit.Client{
		API:          &apic,
		TokenManager: &authc,
	}

	secretA := "this is my secret"
	secretB := "this is another secret"
	secretC := "this is yet another secret"

	encryptedBatch, err := transitc.EncryptBatch(ctx, transitKey, []byte(secretA), []byte(secretB), []byte(secretC))
	require.NoError(t, err, "Encryption failure")
	require.NotEmpty(t, encryptedBatch, "Encrypted batch is empty")
	require.Equal(t, 3, len(encryptedBatch), "Incorrect number of encrypted items")

	for _, encrypted := range encryptedBatch {
		require.True(t, strings.HasPrefix(encrypted, "vault:v1:"))
	}
}

func TestDecryptDecryptsData(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		ClientToken: "vault token",
	}
	tokenManager := authmocks.TokenManager{}
	tokenManager.On("GetToken").Return(&token, nil)

	// Set up mocked API response
	resBody := "{\"data\": {\"plaintext\": \"dGhpcyBpcyBteSBzZWNyZXQ=\"}}"
	res := api.Response{
		StatusCode: 200,
		RawBody:    io.NopCloser(strings.NewReader(resBody)),
	}

	transitKey := "my-key"
	encrypted := "vault:v1:asdfasdfasdf"

	// Set up mock API
	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/transit/decrypt/"+transitKey, token.ClientToken, mock.MatchedBy(func(input interface{}) bool {
		actualReqBody, _ := json.Marshal(input)
		return assert.JSONEq(t, fmt.Sprintf("{\"ciphertext\": \"%s\"}", encrypted), string(actualReqBody))
	})).Return(&res, nil)

	transitc := transit.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}
	decrypted, err := transitc.Decrypt(ctx, transitKey, encrypted)
	require.NoError(t, err, "Decryption failure")
	require.NotEmpty(t, encrypted, "Decrypted value is empty")
	require.Equal(t, "this is my secret", string(decrypted), "Decrypted value is not equal to the original")
}

func TestDecryptReturnsErrorOnRequestFailure(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		ClientToken: "vault token",
	}
	tokenManager := authmocks.TokenManager{}
	tokenManager.On("GetToken").Return(&token, nil)

	// Set up mocked API request error
	resErr := errors.New("failed request")

	transitKey := "my-key"

	// Set up mock API
	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/transit/decrypt/"+transitKey, token.ClientToken, mock.Anything).Return(nil, resErr)

	transitc := transit.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}
	decrypted, err := transitc.Decrypt(ctx, transitKey, "vault:v1:asdfasdfasdf")
	require.Error(t, err, "Error does not exist")
	require.ErrorIs(t, err, resErr, "Error is incorrect")
	require.Empty(t, decrypted, "Decrypted value is not empty")
}

func TestDecryptReturnsErrorOnInvalidResponseCode(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		ClientToken: "vault token",
	}
	tokenManager := authmocks.TokenManager{}
	tokenManager.On("GetToken").Return(&token, nil)

	// Set up mocked API response with valid body but incorrect status code
	resBody := "{\"data\": {\"plaintext\": \"dGhpcyBpcyBteSBzZWNyZXQ=\"}}"
	res := api.Response{
		StatusCode: 418,
		RawBody:    io.NopCloser(strings.NewReader(resBody)),
	}

	transitKey := "my-key"

	// Set up mock API
	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/transit/decrypt/"+transitKey, token.ClientToken, mock.Anything).Return(&res, nil)

	transitc := transit.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}
	decrypted, err := transitc.Decrypt(ctx, transitKey, "vault:v1:asdfasdfasdf")
	require.Error(t, err, "Error does not exist")
	require.Errorf(t, err, "received invalid status code 418 for http request")
	require.Empty(t, decrypted, "Encrypted value is not empty")
}

func TestDecryptReturnsErrorOnInvalidJSONResponse(t *testing.T) {
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

	transitKey := "my-key"

	// Set up mock API
	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/transit/decrypt/"+transitKey, token.ClientToken, mock.Anything).Return(&res, nil)

	transitc := transit.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}
	decrypted, err := transitc.Decrypt(ctx, transitKey, "vault:v1:asdfasdfasdf")
	require.Error(t, err, "Error does not exist")
	require.Empty(t, decrypted, "Decrypted value is not empty")
}

func TestDecryptReturnsErrorOnInvalidBase64Response(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		ClientToken: "vault token",
	}
	tokenManager := authmocks.TokenManager{}
	tokenManager.On("GetToken").Return(&token, nil)

	// Set up mocked API response with invalid JSON
	resBody := "{\"data\": {\"plaintext\": \"invalidbase64\"}}"
	res := api.Response{
		StatusCode: 200,
		RawBody:    io.NopCloser(strings.NewReader(resBody)),
	}

	transitKey := "my-key"

	// Set up mock API
	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/transit/decrypt/"+transitKey, token.ClientToken, mock.Anything).Return(&res, nil)

	transitc := transit.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}
	decrypted, err := transitc.Decrypt(ctx, transitKey, "vault:v1:asdfasdfasdf")
	require.Error(t, err, "Error does not exist")
	require.Empty(t, decrypted, "Decrypted value is not empty")
}

func TestIntegrationDecryptDecryptsData(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	vaultContainer, err := testcontainervault.NewContainer(ctx)
	require.NoError(t, err, "Failed to set up Vault container")
	defer vaultContainer.Terminate(ctx)

	err = vaultContainer.EnableTransit(ctx)
	require.NoError(t, err, "Failed to initialize Vault container")

	transitKey := "my-key"
	err = vaultContainer.CreateTransitKey(ctx, transitKey)
	require.NoError(t, err, "Failed to create Vault transit key")

	apic := api.Client{
		HTTP: cleanhttp.DefaultClient(),
		URL:  vaultContainer.URI,
	}

	authc := auth.Client{
		API: &apic,
	}
	authc.SetToken(&auth.Token{ClientToken: vaultContainer.Token})

	transitc := transit.Client{
		API:          &apic,
		TokenManager: &authc,
	}

	plaintext := "this is my secret"

	encrypted, err := transitc.Encrypt(ctx, transitKey, []byte(plaintext))
	require.NoError(t, err, "Encryption failure")
	require.NotEmpty(t, encrypted, "Encrypted value is empty")

	decrypted, err := transitc.Decrypt(ctx, transitKey, encrypted)
	require.NoError(t, err, "Decryption failure")
	require.NotEmpty(t, encrypted, "Decrypted value is empty")
	require.Equal(t, plaintext, string(decrypted), "Decrypted value is not equal to the original")
}

func TestDecryptBatchDecryptsData(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		ClientToken: "vault token",
	}
	tokenManager := authmocks.TokenManager{}
	tokenManager.On("GetToken").Return(&token, nil)

	secretA := "this is my secret"
	secretAEncrypted := "vault:v1:asdfasdfasdf"
	secretB := "this is another secret"
	secretBEncrypted := "vault:v1:qwertyqwerty"
	secretC := "this is yet another secret"
	secretCEncrypted := "vault:v1:zxcvbnzxcvbn"

	// Set up mocked API response
	resBody := `{
		"data": {
			"batch_results": [
				{"plaintext": "dGhpcyBpcyBteSBzZWNyZXQ="},
				{"plaintext": "dGhpcyBpcyBhbm90aGVyIHNlY3JldA=="},
				{"plaintext": "dGhpcyBpcyB5ZXQgYW5vdGhlciBzZWNyZXQ="}
			]
		}
	}`
	res := api.Response{
		StatusCode: 200,
		RawBody:    io.NopCloser(strings.NewReader(resBody)),
	}

	transitKey := "my-key"

	// Set up mock API
	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/transit/decrypt/"+transitKey, token.ClientToken, mock.MatchedBy(func(input interface{}) bool {
		actualReqBody, _ := json.Marshal(input)
		expectedReqBody := fmt.Sprintf(`{
			"batch_input": [
				{"ciphertext": "%s"},
				{"ciphertext": "%s"},
				{"ciphertext": "%s"}
			]
		}`, secretAEncrypted, secretBEncrypted, secretCEncrypted)
		return assert.JSONEq(t, expectedReqBody, string(actualReqBody))
	})).Return(&res, nil)

	transitc := transit.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	decryptedBatch, err := transitc.DecryptBatch(ctx, transitKey, secretAEncrypted, secretBEncrypted, secretCEncrypted)
	require.NoError(t, err, "Decryption failure")
	require.NotEmpty(t, decryptedBatch, "Decrypted batch is empty")
	require.Equal(t, 3, len(decryptedBatch), "Incorrect number of decrypted items")
	require.Equal(t, secretA, string(decryptedBatch[0]))
	require.Equal(t, secretB, string(decryptedBatch[1]))
	require.Equal(t, secretC, string(decryptedBatch[2]))
}

func TestDecryptBatchReturnsErrorOnRequestFailure(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		ClientToken: "vault token",
	}
	tokenManager := authmocks.TokenManager{}
	tokenManager.On("GetToken").Return(&token, nil)

	// Set up mocked API request error
	resErr := errors.New("failed request")

	transitKey := "my-key"

	// Set up mock API
	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/transit/decrypt/"+transitKey, token.ClientToken, mock.Anything).Return(nil, resErr)

	transitc := transit.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	decryptedBatch, err := transitc.DecryptBatch(ctx, transitKey, "vault:v1:asdfasdfasdf", "vault:v1:qwertyqwerty", "vault:v1:zxcvbnzxcvbn")
	require.Error(t, err, "Error does not exist")
	require.ErrorIs(t, err, resErr, "Error is incorrect")
	require.Empty(t, decryptedBatch, "Decrypted batch is not empty")
}

func TestDecryptBatchReturnsErrorOnInvalidResponseCode(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		ClientToken: "vault token",
	}
	tokenManager := authmocks.TokenManager{}
	tokenManager.On("GetToken").Return(&token, nil)

	// Set up mocked API response with valid body but incorrect status code
	resBody := `{
		"data": {
			"batch_results": [
				{"plaintext": "dGhpcyBpcyBteSBzZWNyZXQ="},
				{"plaintext": "dGhpcyBpcyBhbm90aGVyIHNlY3JldA=="},
				{"plaintext": "dGhpcyBpcyB5ZXQgYW5vdGhlciBzZWNyZXQ="}
			]
		}
	}`
	res := api.Response{
		StatusCode: 418,
		RawBody:    io.NopCloser(strings.NewReader(resBody)),
	}

	transitKey := "my-key"

	// Set up mock API
	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/transit/decrypt/"+transitKey, token.ClientToken, mock.Anything).Return(&res, nil)

	transitc := transit.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	decryptedBatch, err := transitc.DecryptBatch(ctx, transitKey, "vault:v1:asdfasdfasdf", "vault:v1:qwertyqwerty", "vault:v1:zxcvbnzxcvbn")
	require.Error(t, err, "Error does not exist")
	require.Errorf(t, err, "received invalid status code 418 for http request")
	require.Empty(t, decryptedBatch, "Encrypted batch is not empty")
}

func TestDecryptBatchReturnsErrorOnInvalidJSONResponse(t *testing.T) {
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

	transitKey := "my-key"

	// Set up mock API
	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/transit/decrypt/"+transitKey, token.ClientToken, mock.Anything).Return(&res, nil)

	transitc := transit.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	decryptedBatch, err := transitc.DecryptBatch(ctx, transitKey, "vault:v1:asdfasdfasdf", "vault:v1:qwertyqwerty", "vault:v1:zxcvbnzxcvbn")
	require.Error(t, err, "Error does not exist")
	require.Empty(t, decryptedBatch, "Decrypted value is not empty")
}

func TestDecryptBatchReturnsErrorOnInvalidBase64Response(t *testing.T) {
	ctx := context.Background()

	// Set up token manager
	token := auth.Token{
		ClientToken: "vault token",
	}
	tokenManager := authmocks.TokenManager{}
	tokenManager.On("GetToken").Return(&token, nil)

	// Set up mocked API response with invalid base64
	resBody := `{
		"data": {
			"batch_results": [
				{"plaintext": "dGhpcyBpcyBteSBzZWNyZXQ="},
				{"plaintext": "invalidbase64"},
				{"plaintext": "dGhpcyBpcyB5ZXQgYW5vdGhlciBzZWNyZXQ="}
			]
		}
	}`
	res := api.Response{
		StatusCode: 200,
		RawBody:    io.NopCloser(strings.NewReader(resBody)),
	}

	transitKey := "my-key"

	// Set up mock API
	apic := apimocks.API{}
	apic.On("Write", ctx, "/v1/transit/decrypt/"+transitKey, token.ClientToken, mock.Anything).Return(&res, nil)

	transitc := transit.Client{
		API:          &apic,
		TokenManager: &tokenManager,
	}

	decryptedBatch, err := transitc.DecryptBatch(ctx, transitKey, "vault:v1:asdfasdfasdf", "vault:v1:qwertyqwerty", "vault:v1:zxcvbnzxcvbn")
	require.Error(t, err, "Error does not exist")
	require.Empty(t, decryptedBatch, "Decrypted value is not empty")
}

func TestIntegrationDecryptBatchDecryptsData(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	vaultContainer, err := testcontainervault.NewContainer(ctx)
	require.NoError(t, err, "Failed to set up Vault container")
	defer vaultContainer.Terminate(ctx)

	err = vaultContainer.EnableTransit(ctx)
	require.NoError(t, err, "Failed to initialize Vault container")

	transitKey := "my-key"
	err = vaultContainer.CreateTransitKey(ctx, transitKey)
	require.NoError(t, err, "Failed to create Vault transit key")

	apic := api.Client{
		HTTP: cleanhttp.DefaultClient(),
		URL:  vaultContainer.URI,
	}

	authc := auth.Client{
		API: &apic,
	}
	authc.SetToken(&auth.Token{ClientToken: vaultContainer.Token})

	transitc := transit.Client{
		API:          &apic,
		TokenManager: &authc,
	}

	secretA := "this is my secret"
	secretB := "this is another secret"
	secretC := "this is yet another secret"

	encryptedBatch, err := transitc.EncryptBatch(ctx, transitKey, []byte(secretA), []byte(secretB), []byte(secretC))
	require.NoError(t, err, "Encryption failure")
	require.NotEmpty(t, encryptedBatch, "Encrypted batch is empty")
	require.Equal(t, 3, len(encryptedBatch), "Incorrect number of encrypted items")

	decryptedBatch, err := transitc.DecryptBatch(ctx, transitKey, encryptedBatch...)
	require.NoError(t, err, "Decryption failure")
	require.NotEmpty(t, encryptedBatch, "Decrypted batch is empty")
	require.Equal(t, 3, len(encryptedBatch), "Incorrect number of decrypted items")
	require.Equal(t, secretA, string(decryptedBatch[0]), "Decrypted value is not equal to the original")
	require.Equal(t, secretB, string(decryptedBatch[1]), "Decrypted value is not equal to the original")
	require.Equal(t, secretC, string(decryptedBatch[2]), "Decrypted value is not equal to the original")
}
