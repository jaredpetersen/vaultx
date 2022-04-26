package transit

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/jaredpetersen/vaultx/api"
	"github.com/jaredpetersen/vaultx/auth"
)

// Client is a gateway into the functionality provided by Vault's transit secret engine.
//
// For more information, see https://www.vaultproject.io/docs/secrets/transit.
type Client struct {
	API          api.API
	TokenManager auth.TokenManager
}

const httpPathTransitEncrypt = "/v1/transit/encrypt/"
const httpPathTransitDecrypt = "/v1/transit/decrypt/"

// Encrypt encrypts data into a Vault ciphertext.
func (t *Client) Encrypt(ctx context.Context, key string, data []byte) (string, error) {
	// Encode the data as a base64 string
	reqBody := struct {
		Plaintext string `json:"plaintext"`
	}{
		Plaintext: base64.StdEncoding.EncodeToString(data),
	}

	res, err := t.API.Write(ctx, httpPathTransitEncrypt+key, t.TokenManager.GetToken().Value, reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to perform encryption request: %w", err)
	}

	if res.StatusCode != 200 {
		return "", fmt.Errorf("received invalid status code %d for http request", res.StatusCode)
	}

	type responseData struct {
		Ciphertext string `json:"ciphertext"`
	}
	type response struct {
		Data responseData `json:"data"`
	}

	resBody := new(response)
	err = res.JSON(resBody)
	if err != nil {
		return "", fmt.Errorf("failed to map request response: %w", err)
	}

	return resBody.Data.Ciphertext, nil
}

// EncryptBatch encrypts multiple data items into Vault ciphertexts.
func (t *Client) EncryptBatch(ctx context.Context, key string, data ...[]byte) ([]string, error) {
	type requestBatchInput struct {
		Plaintext string `json:"plaintext"`
	}
	type request struct {
		BatchInput []requestBatchInput `json:"batch_input"`
	}

	reqBody := request{
		BatchInput: []requestBatchInput{},
	}

	// Encode the data as base64 strings
	for _, item := range data {
		input := requestBatchInput{
			Plaintext: base64.StdEncoding.EncodeToString(item),
		}
		reqBody.BatchInput = append(reqBody.BatchInput, input)
	}

	res, err := t.API.Write(ctx, httpPathTransitEncrypt+key, t.TokenManager.GetToken().Value, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to perform batch encryption request: %w", err)
	}

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("received invalid status code %d for http request", res.StatusCode)
	}

	type response struct {
		Data struct {
			BatchResults []struct {
				Ciphertext string `json:"ciphertext"`
			} `json:"batch_results"`
		} `json:"data"`
	}

	resBody := new(response)
	err = res.JSON(resBody)
	if err != nil {
		return nil, fmt.Errorf("failed to map request response: %w", err)
	}

	var ciphertexts []string
	for _, encryptResult := range resBody.Data.BatchResults {
		ciphertexts = append(ciphertexts, encryptResult.Ciphertext)
	}

	return ciphertexts, nil
}

// Decrypt decrypts a Vault ciphertext.
func (t *Client) Decrypt(ctx context.Context, key string, ciphertext string) ([]byte, error) {
	reqBody := struct {
		Ciphertext string `json:"ciphertext"`
	}{
		Ciphertext: ciphertext,
	}

	res, err := t.API.Write(ctx, httpPathTransitDecrypt+key, t.TokenManager.GetToken().Value, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to perform decryption request: %w", err)
	}

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("received invalid status code %d for http request", res.StatusCode)
	}

	type response struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}

	resBody := new(response)
	err = res.JSON(resBody)
	if err != nil {
		return nil, fmt.Errorf("failed to map request response: %w", err)
	}

	// Decode the data via base64
	// Handle the error since decode can still return data when there is an error
	decrypted, err := base64.StdEncoding.DecodeString(resBody.Data.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode secret: %w", err)
	}

	return decrypted, nil
}

// DecryptBatch decrypts multiple data items into Vault ciphertexts.
func (t *Client) DecryptBatch(ctx context.Context, key string, ciphertexts ...string) ([][]byte, error) {
	type requestBatchInput struct {
		Ciphertext string `json:"ciphertext"`
	}
	type request struct {
		BatchInput []requestBatchInput `json:"batch_input"`
	}

	reqBody := request{
		BatchInput: []requestBatchInput{},
	}

	for _, ciphertext := range ciphertexts {
		input := requestBatchInput{
			Ciphertext: ciphertext,
		}
		reqBody.BatchInput = append(reqBody.BatchInput, input)
	}

	res, err := t.API.Write(ctx, httpPathTransitDecrypt+key, t.TokenManager.GetToken().Value, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to perform batch decryption request: %w", err)
	}

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("received invalid status code %d for http request", res.StatusCode)
	}

	type response struct {
		Data struct {
			BatchResults []struct {
				Plaintext string `json:"plaintext"`
			} `json:"batch_results"`
		} `json:"data"`
	}

	resBody := new(response)
	err = res.JSON(resBody)
	if err != nil {
		return nil, fmt.Errorf("failed to map request response: %w", err)
	}

	// Decode the data using base64
	var decryptedItems [][]byte
	for _, batchResult := range resBody.Data.BatchResults {
		decryptedItem, err := base64.StdEncoding.DecodeString(batchResult.Plaintext)
		if err != nil {
			return nil, fmt.Errorf("failed to base64 decode secret: %w", err)
		}

		decryptedItems = append(decryptedItems, decryptedItem)
	}

	return decryptedItems, nil
}
