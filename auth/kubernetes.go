package auth

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jaredpetersen/vaultx/api"
)

const httpPathAuthKubernetesLogin = "/v1/auth/kubernetes/login"
const defaultKubernetesServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// KubernetesConfig describes the configuration necessary for KubernetesMethod.
type KubernetesConfig struct {
	// Role is the AuthMethod service account role that should be used to authenticate with Vault.
	Role string

	// JWTProvider is an optional field used to override how the Kubernetes service account JWT is retrieved for use
	// when authenticating with Vault. If omitted, the client will read the JWT from the
	// `/var/run/secrets/kubernetes.io/serviceaccount/token` file.
	JWTProvider func() (string, error)
}

// KubernetesMethod enables the Vault client to use authenticate itself with Vault by using the identity established
// by your Kubernetes cluster.
//
// See https://www.vaultproject.io/api-docs/auth/kubernetes for more information on the Kubernetes auth method.
type KubernetesMethod struct {
	Config KubernetesConfig
}

// DefaultKubernetesJWTProvider reads the Kubernetes service account JWT token located
// at /var/run/secrets/kubernetes.io/serviceaccount/token and returns it.
func DefaultKubernetesJWTProvider() (string, error) {
	jwtBytes, err := os.ReadFile(defaultKubernetesServiceAccountTokenPath)
	if err != nil {
		return "", err
	}
	jwt := string(jwtBytes)

	return jwt, nil
}

// NewKubernetesMethod creates a new Vault auth method for Kubernetes.
func NewKubernetesMethod(config KubernetesConfig) KubernetesMethod {
	if config.JWTProvider == nil {
		config.JWTProvider = DefaultKubernetesJWTProvider
	}

	return KubernetesMethod{Config: config}
}

// Login generates a Vault token using the identity established by your Kubernetes cluster.
func (k KubernetesMethod) Login(ctx context.Context, api api.API) (Token, error) {
	jwt, err := k.Config.JWTProvider()
	if err != nil {
		return Token{}, err
	}

	type generateTokenRequest struct {
		JWT  string `json:"jwt"`
		Role string `json:"role"`
	}

	authPayload := generateTokenRequest{
		Role: k.Config.Role,
		JWT:  jwt,
	}

	res, err := api.Write(ctx, httpPathAuthKubernetesLogin, "", authPayload)
	if err != nil {
		return Token{}, err
	}

	if res.StatusCode != 200 {
		return Token{}, fmt.Errorf("received invalid status code %d for http request", res.StatusCode)
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
		return Token{}, err
	}

	token := Token{
		Value:      resBody.Auth.ClientToken,
		Expiration: time.Duration(resBody.Auth.LeaseDuration) * time.Second,
		Renewable:  resBody.Auth.Renewable,
	}

	return token, nil
}
