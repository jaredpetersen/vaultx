// Package db contains all the functionality necessary for interacting with Vault's database secrets engine.
//
// See https://www.vaultproject.io/docs/secrets/databases for more information.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jaredpetersen/vaultx/api"
	"github.com/jaredpetersen/vaultx/auth"
)

// Client is the gateway into Vault's database secrets engine.
type Client struct {
	API          api.API
	TokenManager auth.TokenManager
}

// Credentials contains secret information for connecting to a database.
type Credentials struct {
	Username string
	Password string
	Lease    Lease
}

// Lease contains information about how long the secret is valid.
type Lease struct {
	ID         string
	Renewable  bool
	Expiration time.Duration
}

const httpPathDBCredentials = "/v1/database/creds/"

// GenerateCredentials generates a new set of dynamic credentials based on the role.
func (db *Client) GenerateCredentials(ctx context.Context, role string) (Credentials, error) {
	type credentialsResponse struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	type credentialsResponseWrapper struct {
		LeaseID      string              `json:"lease_id"`
		LaseDuration int                 `json:"lease_duration"`
		Renewable    bool                `json:"renewable"`
		Data         credentialsResponse `json:"data"`
	}

	res, err := db.API.Read(ctx, httpPathDBCredentials+role, db.TokenManager.GetToken().Value)
	if err != nil {
		return Credentials{}, fmt.Errorf("failed to perform database credentials generation request: %w", err)
	}

	if res.StatusCode != 200 {
		return Credentials{}, fmt.Errorf("received invalid status code %d for http request", res.StatusCode)
	}

	resBody := new(credentialsResponseWrapper)
	err = res.JSON(resBody)
	if err != nil {
		return Credentials{}, err
	}

	credentials := Credentials{
		Username: resBody.Data.Username,
		Password: resBody.Data.Password,
		Lease: Lease{
			ID:         resBody.LeaseID,
			Renewable:  resBody.Renewable,
			Expiration: time.Duration(resBody.LaseDuration) * time.Second,
		},
	}

	return credentials, nil
}
