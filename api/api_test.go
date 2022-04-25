package api_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/stretchr/testify/require"

	"github.com/jaredpetersen/vaultx/api"
)

type dummyRequestBody struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

type dummyResponseBody struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Age  int    `json:"age"`
}

const vaultTokenHeader = "x-vault-token"

func TestWriteSendsPostRequest(t *testing.T) {
	ctx := context.Background()

	path := "/user/dummy"
	vaultToken := "vaulttoken"
	reqBody := dummyRequestBody{
		Name: "John",
		Age:  43,
	}

	resBody := dummyResponseBody{
		ID:   "1930ec0f-9c56-4217-bc50-7263595a3958",
		Name: "John",
		Age:  43,
	}
	statusCode := 201

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		require.Equal(t, http.MethodPost, r.Method, "Incorrect HTTP method")
		require.Equal(t, vaultToken, r.Header.Get(vaultTokenHeader))

		body := new(dummyRequestBody)
		err := json.NewDecoder(r.Body).Decode(body)
		require.NoError(t, err, "Failed to decode request body")
		require.Equal(t, *body, reqBody, "Failed to send correct request body")

		dummyBytes, _ := json.Marshal(resBody)

		w.WriteHeader(statusCode)
		w.Write(dummyBytes)
	}))
	defer srv.Close()

	apic := api.Client{
		HTTP: cleanhttp.DefaultClient(),
		URL:  srv.URL,
	}

	res, err := apic.Write(ctx, path, vaultToken, reqBody)
	require.NoError(t, err, "Error exists")
	require.NotEmpty(t, res, "Response is empty")

	require.Equal(t, res.StatusCode, statusCode, "Status code mismatch")

	actualResBody := new(dummyResponseBody)
	err = res.JSON(actualResBody)
	require.NoError(t, err, "Error converting response body to struct")
	require.Equal(t, resBody, *actualResBody, "Response body is incorrect")
}

func TestWriteSendsPostRequestNoBody(t *testing.T) {
	ctx := context.Background()

	path := "/user/dummy"
	vaultToken := "vaulttoken"

	resBody := "responsebody"
	statusCode := 201

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		require.Equal(t, http.MethodPost, r.Method, "Incorrect HTTP method")
		require.Equal(t, vaultToken, r.Header.Get(vaultTokenHeader))

		require.NotEmpty(t, r.Body, "Body is not empty")

		w.WriteHeader(statusCode)
		w.Write([]byte(resBody))
	}))
	defer srv.Close()

	apic := api.Client{
		HTTP: cleanhttp.DefaultClient(),
		URL:  srv.URL,
	}

	res, err := apic.Write(ctx, path, vaultToken, nil)
	require.NoError(t, err, "Error exists")
	require.NotEmpty(t, res, "Response is empty")

	require.Equal(t, res.StatusCode, statusCode, "Status code mismatch")

	actualResBody, err := io.ReadAll(res.RawBody)
	require.NoError(t, err, "Error converting response body")
	require.Equal(t, resBody, string(actualResBody), "Response body is incorrect")
}

func TestWriteSendsPostRequestNoAuth(t *testing.T) {
	ctx := context.Background()

	path := "/user/dummy"

	resBody := "responsebody"
	statusCode := 201

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		require.Equal(t, http.MethodPost, r.Method, "Incorrect HTTP method")
		require.Empty(t, r.Header.Get(vaultTokenHeader))

		require.NotEmpty(t, r.Body, "Body is not empty")

		w.WriteHeader(statusCode)
		w.Write([]byte(resBody))
	}))
	defer srv.Close()

	apic := api.Client{
		HTTP: cleanhttp.DefaultClient(),
		URL:  srv.URL,
	}

	res, err := apic.Write(ctx, path, "", nil)
	require.NoError(t, err, "Error exists")
	require.NotEmpty(t, res, "Response is empty")

	require.Equal(t, res.StatusCode, statusCode, "Status code mismatch")

	actualResBody, err := io.ReadAll(res.RawBody)
	require.NoError(t, err, "Error converting response body")
	require.Equal(t, resBody, string(actualResBody), "Response body is incorrect")
}

func TestWriteReturnsErrorWhenProvidedInvalidBody(t *testing.T) {
	ctx := context.Background()

	path := "/user/dummy"
	vaultToken := "vaulttoken"
	reqBody := make(chan int)

	apic := api.Client{
		HTTP: cleanhttp.DefaultClient(),
		URL:  "https://example.com",
	}

	res, err := apic.Write(ctx, path, vaultToken, reqBody)
	require.Error(t, err, "Error does not exist")
	require.Empty(t, res, "Response is empty")
}

func TestWriteReturnsErrorWhenProvidedInvalidURL(t *testing.T) {
	ctx := context.Background()

	path := "/user/dummy"
	vaultToken := "vaulttoken"
	reqBody := dummyRequestBody{
		Name: "John",
		Age:  43,
	}

	apic := api.Client{
		HTTP: cleanhttp.DefaultClient(),
		URL:  "nOt A vAlId UrL",
	}

	res, err := apic.Write(ctx, path, vaultToken, reqBody)
	require.Error(t, err, "Error does not exist")
	require.Empty(t, res, "Response is empty")
}

func TestReadSendsGetRequest(t *testing.T) {
	ctx := context.Background()

	path := "/user/dummy"
	vaultToken := "vaulttoken"

	resBody := dummyResponseBody{
		ID:   "1930ec0f-9c56-4217-bc50-7263595a3958",
		Name: "John",
		Age:  43,
	}
	statusCode := 200

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method, "Incorrect HTTP method")
		require.Equal(t, vaultToken, r.Header.Get(vaultTokenHeader))

		dummyBytes, _ := json.Marshal(resBody)

		w.WriteHeader(statusCode)
		w.Write(dummyBytes)
	}))
	defer srv.Close()

	apic := api.Client{
		HTTP: cleanhttp.DefaultClient(),
		URL:  srv.URL,
	}

	res, err := apic.Read(ctx, path, vaultToken)
	require.NoError(t, err, "Error exists")
	require.NotEmpty(t, res, "Response is empty")

	require.Equal(t, res.StatusCode, statusCode, "Status code mismatch")

	actualResBody := new(dummyResponseBody)
	err = res.JSON(actualResBody)
	require.NoError(t, err, "Error converting response body to struct")
	require.Equal(t, resBody, *actualResBody, "Response body is incorrect")
}

func TestReadSendsGetRequestNoAuth(t *testing.T) {
	ctx := context.Background()

	path := "/user/dummy"

	resBody := dummyResponseBody{
		ID:   "1930ec0f-9c56-4217-bc50-7263595a3958",
		Name: "John",
		Age:  43,
	}
	statusCode := 200

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method, "Incorrect HTTP method")
		require.Empty(t, r.Header.Get(vaultTokenHeader))

		dummyBytes, _ := json.Marshal(resBody)

		w.WriteHeader(statusCode)
		w.Write(dummyBytes)
	}))
	defer srv.Close()

	apic := api.Client{
		HTTP: cleanhttp.DefaultClient(),
		URL:  srv.URL,
	}

	res, err := apic.Read(ctx, path, "")
	require.NoError(t, err, "Error exists")
	require.NotEmpty(t, res, "Response is empty")

	require.Equal(t, res.StatusCode, statusCode, "Status code mismatch")

	actualResBody := new(dummyResponseBody)
	err = res.JSON(actualResBody)
	require.NoError(t, err, "Error converting response body to struct")
	require.Equal(t, resBody, *actualResBody, "Response body is incorrect")
}

func TestGetReturnsErrorWhenProvidedInvalidURL(t *testing.T) {
	ctx := context.Background()

	path := "/user/dummy"
	vaultToken := "vaulttoken"

	apic := api.Client{
		HTTP: cleanhttp.DefaultClient(),
		URL:  "nOt A vAlId UrL",
	}

	res, err := apic.Read(ctx, path, vaultToken)
	require.Error(t, err, "Error does not exist")
	require.Empty(t, res, "Response is empty")
}
