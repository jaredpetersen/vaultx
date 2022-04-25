package vaultx_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jaredpetersen/vaultx/kv"

	"github.com/jaredpetersen/vaultx"
	vaultxauth "github.com/jaredpetersen/vaultx/auth"
	"github.com/jaredpetersen/vaultx/internal/testcontainerpostgres"
	"github.com/jaredpetersen/vaultx/internal/testcontainervault"
)

func TestIntegrationAPIReadSendsGetRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	vaultContainer, err := testcontainervault.NewContainer(ctx)
	require.NoError(t, err, "Failed to set up Vault container")
	defer vaultContainer.Terminate(ctx)

	cfg := vaultx.NewConfig(vaultContainer.URI)
	vltx := vaultx.New(cfg)

	path := "/v1/sys/health"

	res, err := vltx.API.Read(ctx, path, vaultContainer.Token)
	require.NoError(t, err, "Error exists")
	require.NotEmpty(t, res, "Response is empty")

	type responseBody struct {
		Initialized bool   `json:"initialized"`
		Sealed      bool   `json:"sealed"`
		Standby     bool   `json:"standby"`
		Version     string `json:"version"`
	}

	expectedResBody := responseBody{
		Initialized: true,
		Sealed:      false,
		Standby:     false,
		Version:     "1.9.4",
	}

	actualResBody := new(responseBody)
	err = res.JSON(&actualResBody)
	require.NoError(t, err, "Error converting response body to struct")

	require.Equal(t, 200, res.StatusCode, "Status code mismatch")
	require.Equal(t, expectedResBody, *actualResBody, "Response body is incorrect")
}

func TestIntegrationAPIWriteSendsPostRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	vaultContainer, err := testcontainervault.NewContainer(ctx)
	require.NoError(t, err, "Failed to set up Vault container")
	defer vaultContainer.Terminate(ctx)

	cfg := vaultx.NewConfig(vaultContainer.URI)
	vltx := vaultx.New(cfg)

	path := "/v1/secret/data/newsecret"

	type requestWrapper struct {
		Data map[string]interface{} `json:"data"`
	}

	req := requestWrapper{
		Data: map[string]interface{}{
			"password": "BVthg8C4VGpkqVQk2gArykTB",
		},
	}

	res, err := vltx.API.Write(ctx, path, vaultContainer.Token, req)
	require.NoError(t, err, "Error exists")
	require.NotEmpty(t, res, "Response is empty")

	type response struct {
		Version int `json:"version"`
	}

	type responseWrapper struct {
		Data response `json:"data"`
	}

	expectedResBody := responseWrapper{
		Data: response{
			Version: 1,
		},
	}

	actualResBody := new(responseWrapper)
	err = res.JSON(&actualResBody)
	require.NoError(t, err, "Error converting response body to struct")

	require.Equal(t, 200, res.StatusCode, "Status code mismatch")
	require.Equal(t, expectedResBody, *actualResBody, "Response body is incorrect")
}

func TestIntegrationDBGenerateCredentialsReturnsCredentials(t *testing.T) {
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

	cfg := vaultx.NewConfig(vaultContainer.URI)
	vltx := vaultx.New(cfg)
	vltx.Auth.SetToken(&vaultxauth.Token{ClientToken: vaultContainer.Token})

	dbCredentials, err := vltx.DB.GenerateCredentials(ctx, dbRole)
	require.NoError(t, err, "Credential generation failure")
	require.NotEmpty(t, dbCredentials, "Credentials are empty")
	require.NotEmpty(t, dbCredentials.Username, "Username is empty")
	require.NotEqual(t, dbUser, dbCredentials.Username, "Username matches original credentials")
	require.True(t, strings.HasPrefix(dbCredentials.Username, "v-token-"+dbRole))
	require.NotEmpty(t, dbCredentials.Password, "Password is empty")
	require.NotEqual(t, dbPassword, dbCredentials.Password, "Password matches original credentials")
}

func TestIntegrationKVUpsertGetSecretReturnsSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	vaultContainer, err := testcontainervault.NewContainer(ctx)
	require.NoError(t, err, "Failed to set up Vault container")
	defer vaultContainer.Terminate(ctx)

	cfg := vaultx.NewConfig(vaultContainer.URI)
	vltx := vaultx.New(cfg)
	vltx.Auth.SetToken(&vaultxauth.Token{ClientToken: vaultContainer.Token})

	secretPath := "mypath"
	secretData := map[string]interface{}{
		"username": "dbuser",
		"password": "3hvu2ZLxwauHrNaZjJbJARHE",
	}

	err = vltx.KV.UpsertSecret(ctx, secretPath, secretData)
	require.NoError(t, err, "Upsert failure")

	expectedSecret := kv.Secret{
		Data:    secretData,
		Version: 1,
	}

	secret, err := vltx.KV.GetSecret(ctx, secretPath)
	require.NoError(t, err, "Get failure")
	require.NotEmpty(t, secret, "Secret is empty")
	require.Equal(t, expectedSecret, *secret, "Secret is incorrect")
}

func TestIntegrationTransitEncryptEncryptsData(t *testing.T) {
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

	cfg := vaultx.NewConfig(vaultContainer.URI)
	vltx := vaultx.New(cfg)
	vltx.Auth.SetToken(&vaultxauth.Token{ClientToken: vaultContainer.Token})

	plaintext := "this is my secret"
	encrypted, err := vltx.Transit.Encrypt(ctx, transitKey, []byte(plaintext))
	require.NoError(t, err, "Encryption failure")
	require.NotEmpty(t, encrypted, "Encrypted value is empty")
	require.True(t, strings.HasPrefix(encrypted, "vault:v1:"))
}

func TestIntegrationTransitEncryptBatchEncryptsData(t *testing.T) {
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

	cfg := vaultx.NewConfig(vaultContainer.URI)
	vltx := vaultx.New(cfg)
	vltx.Auth.SetToken(&vaultxauth.Token{ClientToken: vaultContainer.Token})

	secretA := "this is my secret"
	secretB := "this is another secret"
	secretC := "this is yet another secret"

	encryptedBatch, err := vltx.Transit.EncryptBatch(ctx, transitKey, []byte(secretA), []byte(secretB), []byte(secretC))
	require.NoError(t, err, "Encryption failure")
	require.NotEmpty(t, encryptedBatch, "Encrypted batch is empty")
	require.Equal(t, 3, len(encryptedBatch), "Incorrect number of encrypted items")

	for _, encrypted := range encryptedBatch {
		require.True(t, strings.HasPrefix(encrypted, "vault:v1:"))
	}
}

func TestIntegrationTransitDecryptDecryptsData(t *testing.T) {
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

	cfg := vaultx.NewConfig(vaultContainer.URI)
	vltx := vaultx.New(cfg)
	vltx.Auth.SetToken(&vaultxauth.Token{ClientToken: vaultContainer.Token})

	plaintext := "this is my secret"

	encrypted, err := vltx.Transit.Encrypt(ctx, transitKey, []byte(plaintext))
	require.NoError(t, err, "Encryption failure")
	require.NotEmpty(t, encrypted, "Encrypted value is empty")

	decrypted, err := vltx.Transit.Decrypt(ctx, transitKey, encrypted)
	require.NoError(t, err, "Decryption failure")
	require.NotEmpty(t, encrypted, "Decrypted value is empty")
	require.Equal(t, plaintext, string(decrypted), "Decrypted value is not equal to the original")
}

func TestIntegrationTransitDecryptBatchDecryptsData(t *testing.T) {
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

	cfg := vaultx.NewConfig(vaultContainer.URI)
	vltx := vaultx.New(cfg)
	vltx.Auth.SetToken(&vaultxauth.Token{ClientToken: vaultContainer.Token})

	secretA := "this is my secret"
	secretB := "this is another secret"
	secretC := "this is yet another secret"

	encryptedBatch, err := vltx.Transit.EncryptBatch(ctx, transitKey, []byte(secretA), []byte(secretB), []byte(secretC))
	require.NoError(t, err, "Encryption failure")
	require.NotEmpty(t, encryptedBatch, "Encrypted batch is empty")
	require.Equal(t, 3, len(encryptedBatch), "Incorrect number of encrypted items")

	decryptedBatch, err := vltx.Transit.DecryptBatch(ctx, transitKey, encryptedBatch...)
	require.NoError(t, err, "Decryption failure")
	require.NotEmpty(t, encryptedBatch, "Decrypted batch is empty")
	require.Equal(t, 3, len(encryptedBatch), "Incorrect number of decrypted items")
	require.Equal(t, secretA, string(decryptedBatch[0]), "Decrypted value is not equal to the original")
	require.Equal(t, secretB, string(decryptedBatch[1]), "Decrypted value is not equal to the original")
	require.Equal(t, secretC, string(decryptedBatch[2]), "Decrypted value is not equal to the original")
}
