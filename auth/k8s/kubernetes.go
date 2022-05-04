package k8s

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jaredpetersen/vaultx/api"
	"github.com/jaredpetersen/vaultx/auth"
)

const httpPathAuthKubernetesLogin = "/v1/auth/kubernetes/login"
const defaultKubernetesServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

type Config struct {
	// Role is the AuthMethod service account role that should be used to authenticate with Vault.
	Role string

	// JWTProvider is an optional field used to override how the Kubernetes service account JWT is retrieved for use
	// when authenticating with Vault. If omitted, the client will read the JWT from the
	// `/var/run/secrets/kubernetes.io/serviceaccount/token` file.
	JWTProvider func() (string, error)
}

// AuthMethod enables the Vault client to use information about your AuthMethod deployment environment to
// authenticate itself with Vault.
//
// See https://www.vaultproject.io/api-docs/auth/kubernetes for more information on the Kubernetes auth method.
type AuthMethod struct {
	Config Config
}

// DefaultJWTProvider is an implementation of JWTProvider that reads the Kubernetes service account JWT token located
// at /var/run/secrets/kubernetes.io/serviceaccount/token and returns it.
func DefaultJWTProvider() (string, error) {
	jwtBytes, err := os.ReadFile(defaultKubernetesServiceAccountTokenPath)
	if err != nil {
		return "", err
	}
	jwt := string(jwtBytes)

	return jwt, nil
}

// New creates a new Vault auth method for Kubernetes.
func New(config Config) AuthMethod {
	if config.JWTProvider == nil {
		config.JWTProvider = DefaultJWTProvider
	}

	return AuthMethod{Config: config}
}

// Login generates a Vault token using information about the AuthMethod deployment environment.
func (m AuthMethod) Login(ctx context.Context, api api.API) (auth.Token, error) {
	jwt, err := m.Config.JWTProvider()
	if err != nil {
		return auth.Token{}, err
	}

	type generateTokenRequest struct {
		JWT  string `json:"jwt"`
		Role string `json:"role"`
	}

	authPayload := generateTokenRequest{
		Role: m.Config.Role,
		JWT:  jwt,
	}

	res, err := api.Write(ctx, httpPathAuthKubernetesLogin, "", authPayload)
	if err != nil {
		return auth.Token{}, err
	}

	if res.StatusCode != 200 {
		return auth.Token{}, fmt.Errorf("received invalid status code %d for http request", res.StatusCode)
	}

	type kubernetesAuthResponse struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"` // seconds
		Renewable     bool   `json:"renewable"`
	}

	type kubernetesAuthResponseWrapper struct {
		Auth kubernetesAuthResponse `json:"auth"`
	}

	resBody := new(kubernetesAuthResponseWrapper)
	err = res.JSON(resBody)
	if err != nil {
		return auth.Token{}, err
	}

	token := auth.Token{
		Value:      resBody.Auth.ClientToken,
		Expiration: time.Duration(resBody.Auth.LeaseDuration) * time.Second,
		Renewable:  resBody.Auth.Renewable,
	}

	return token, nil
}
