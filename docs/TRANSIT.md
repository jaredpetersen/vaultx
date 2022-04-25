# Transit Secrets Engine
vaultx supports the Vault [Transit secrets engine](https://www.vaultproject.io/docs/secrets/transit) via `Transit` on
the client.

## Usage
Encrypt single value:
```go
transitKey := "my-key"
plaintext := "encrypt me"
encrypted, err := vault.Transit.Encrypt(ctx, transitKey, []byte(plaintext))
if err != nil {
    return err
}

fmt.Printf("encrypted: %s\n", encrypted)
```

Encrypt multiple values in a batch:
```go
transitKey := "my-key"
plaintextA := "encrypt me - a"
plaintextB := "encrypt me - b"
plaintextC := "encrypt me - c"
encryptedBatch, err := vault.Transit.Encrypt(ctx, transitKey, []byte(secretA), []byte(secretB), []byte(secretC))
if err != nil {
    return err
}

fmt.Printf("encrypted a: %s\n", encryptedBatch[0])
fmt.Printf("encrypted b: %s\n", encryptedBatch[1])
fmt.Printf("encrypted c: %s\n", encryptedBatch[2])
```

Decrypt single value:
```go
transitKey := "my-key"
encrypted := "vault:v1:omPRMZNbpOsAD5OdrCy5jI3ggwnFRzCaCj+5j+Fyf/oH"
decrypted, err := vault.Transit.Decrypt(ctx, transitKey, encrypted)
if err != nil {
    return err
}

fmt.Printf("decrypted: %s\n", string(decrypted))
```

Decrypt multiple values in a batch:
```go
transitKey := "my-key"
encryptedA := "vault:v1:omPRMZNbpOsAD5OdrCy5jI3ggwnFRzCaCj+5j+Fyf/oH"
encryptedB := "vault:v1:kG6uQwyZ4kRC1Bx02d3K12cduqB9kx2ltF3WdtHOqbzVusO5"
decrypted, err := vault.Transit.Decrypt(ctx, transitKey, encryptedA, encryptedB)
if err != nil {
    return err
}

fmt.Printf("decrypted a: %s\n", string(decrypted[0]))
fmt.Printf("decrypted b: %s\n", string(decrypted[1]))
```