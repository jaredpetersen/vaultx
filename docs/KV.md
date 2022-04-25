# KV Secrets Engine
vaultx supports the Vault [KV secrets engine](https://www.vaultproject.io/docs/secrets/kv) via `KV` on the client.

## Usage
Store secret:
```go
// Store secret
secretData := map[string]interface{}{
    "username": "dbuser",
    "password": "3hvu2ZLxwauHrNaZjJbJARHE",
}
err := vltx.KV.UpsertSecret(ctx, secretPath, secretData)
if err != nil {
	return err
}
```

Retrieve secret:
```go
secret, err := vltx.KV.GetSecret(ctx, secretPath)
if err != nil {
	return err
}

fmt.Printf("secret username: %s\n", secret.Data["username"])
fmt.Printf("secret password: %s\n", secret.Data["password"])
```