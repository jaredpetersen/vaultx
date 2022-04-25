# Database Secrets Engine
vaultx supports the Vault [database secrets engine](https://www.vaultproject.io/docs/secrets/databases) via `DB` on
the client.

## Usage
Generate credentials:
```go
dbRole := "my-role"
dbCredentials, err := vltx.DB.GenerateCredentials(ctx, dbRole)
if err != nil {
    return err
}

fmt.Printf("username: %s\n", dbCredentials.Username)
fmt.Printf("username: %s\n", dbCredentials.Password)
```