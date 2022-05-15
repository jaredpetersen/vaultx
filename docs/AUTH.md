# Authentication
There are [several ways to authenticate with Vault](https://www.vaultproject.io/docs/auth) but unfortunately, not all
of them are supported by vaultx at this time.

## Kubernetes Auth Method
```go
cfg := vaultx.NewConfig("https://vault.mydomain.com")
cfg.Auth.Method = vaultxauth.NewKubernetesAuthMethod(vaultxauth.KubernetesConfig{Role: vaultConfig.Role})

vltx := vaultx.New(cfg)
```
