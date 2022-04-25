package auth

import (
	"context"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/jaredpetersen/vaultx/api"
)

const httpPathAuthKubernetesLogin = "/v1/auth/kubernetes/login"
const defaultKubernetesServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

type KubernetesConfig struct {
	// Role is the KubernetesAuthMethod service account role that should be used to authenticate with Vault.
	Role string

	// JWTProvider is an optional field used to override how the KubernetesAuthMethod auth method gets the service account JWT
	// used to authenticate with Vault. If omitted, the client will read the JWT from the
	// `/var/run/secrets/kubernetes.io/serviceaccount/token` file.
	JWTProvider func() (string, error)
}

// KubernetesAuthMethod enables the Vault client to use information about your KubernetesAuthMethod deployment environment to
// authenticate itself with Vault.
//
// See https://www.vaultproject.io/api-docs/auth/kubernetes for more information on the KubernetesAuthMethod auth method.
type KubernetesAuthMethod struct {
	Config KubernetesConfig
}

func defaultJWTProvider() (string, error) {
	jwtBytes, err := ioutil.ReadFile(defaultKubernetesServiceAccountTokenPath)
	if err != nil {
		return "", err
	}
	jwt := string(jwtBytes)

	return jwt, nil
}

func NewKubernetesAuthMethod(config KubernetesConfig) KubernetesAuthMethod {
	if config.JWTProvider == nil {
		config.JWTProvider = defaultJWTProvider
	}

	return KubernetesAuthMethod{Config: config}
}

// Login generates a Vault token using information about the KubernetesAuthMethod deployment environment.
func (k KubernetesAuthMethod) Login(ctx context.Context, api api.API) (*Token, error) {
	jwt, err := k.Config.JWTProvider()
	if err != nil {
		return nil, err
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
		return nil, err
	}

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("received invalid status code %d for http request", res.StatusCode)
	}

	type kubernetesAuthResponse struct {
		ClientToken   string `json:"client_token"`
		Accessor      string `json:"accessor"`
		LeaseDuration int    `json:"lease_duration"` // seconds
		Renewable     bool   `json:"renewable"`
	}

	type kubernetesAuthResponseWrapper struct {
		Auth kubernetesAuthResponse `json:"auth"`
	}

	resBody := new(kubernetesAuthResponseWrapper)
	err = res.JSON(resBody)
	if err != nil {
		return nil, err
	}

	token := Token{
		ClientToken: resBody.Auth.ClientToken,
		Accessor:    resBody.Auth.Accessor,
		Lease: TokenLease{
			Duration:  time.Duration(resBody.Auth.LeaseDuration)*time.Second,
			Renewable: resBody.Auth.Renewable,
		},
		Renewable: resBody.Auth.Renewable,
	}

	return &token, nil
}
