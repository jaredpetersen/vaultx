# vaultx
[![Build](https://github.com/jaredpetersen/vaultx/actions/workflows/ci.yaml/badge.svg)](https://github.com/jaredpetersen/vaultx/actions/workflows/ci.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/jaredpetersen/vaultx.svg)](https://pkg.go.dev/github.com/jaredpetersen/vaultx)

vaultx is an alternative to the official Vault Go package that is designed with the developer in mind.

The official Vault package is very useful, but it has a number of issues that make it difficult to integrate Vault
into your applications:
- Tied tightly to the HTTP API, making accomplishing basic functionality involve writing expansive blocks of code
- Types are very generic, so you lose out on type safety and must know the HTTP API in order interact with it
- Automatic renewal of authentication credentials is not well-supported

vaultx seeks to address these issues and make Vault a joy to use in Go.

## Usage
To create your vault client, create a new configuration struct and pass it to vaultx's `New()` function:

```go
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jaredpetersen/vaultx"
	vaultxauth "github.com/jaredpetersen/vaultx/auth"
)

const k8sRole = "my-app"
const vaultKVSecretPath = "my-secret"
const vaultTransitKey = "transit-key"

func main() {
	ctx := context.Background()

	cfg := vaultx.NewConfig("https://vault.mydomain.com")
	cfg.Auth.Method = vaultxauth.NewKubernetesAuthMethod(vaultxauth.KubernetesConfig{Role: k8sRole})

	vltx := vaultx.New(cfg)

	err := vltx.Auth.Login(ctx)
	if err != nil {
		fmt.Println("Failed to authenticate against Vault")
		os.Exit(1)
	}

	// Store secret
	secretData := map[string]interface{}{
		"username": "dbuser",
		"password": "3hvu2ZLxwauHrNaZjJbJARHE",
	}
	err = vltx.KV.UpsertSecret(ctx, vaultKVSecretPath, secretData)
	if err != nil {
		fmt.Println("Failed to store secret")
		os.Exit(1)
	}

	// Get secret
	secret, err := vltx.KV.GetSecret(ctx, vaultKVSecretPath)
	if err != nil {
		fmt.Println("Failed to retrieve secret")
		os.Exit(1)
	}

	fmt.Printf("secret username: %s\n", secret.Data["username"])
	fmt.Printf("secret password: %s\n", secret.Data["password"])

	// Encrypt data
	plaintext := "encrypt me"
	encrypted, err := vltx.Transit.Encrypt(ctx, vaultTransitKey, []byte(plaintext))
	if err != nil {
		fmt.Println("Failed to encrypt data")
		os.Exit(1)
	}

	fmt.Printf("encrypted: %s\n", encrypted)

	// Decrypt data
	decrypted, err := vltx.Transit.Decrypt(ctx, vaultTransitKey, encrypted)
	if err != nil {
		fmt.Println("Failed to decrypt data")
		os.Exit(1)
	}

	fmt.Printf("decrypted: %s\n", string(decrypted))
}

```

## Install
```shell
go get github.com/jaredpetersen/vaultx
```

## Sponsorship
If you or your company uses vaultx, please consider contributing to the project via
[GitHub Sponsors](https://github.com/sponsors/jaredpetersen). There's some cool work that we'd like to do but cloud
computing isn't free.

One thing we'd really like to do is set up web APIs that use vaultx in all the major cloud providers (compute instances
and K8s) so that we can have an end-to-end testing suite that validates that authentication and all the other supported
features work in the real world. We have integration tests that run against Vault containers but there are some
things -- like authentication -- that can't really be tested locally.

