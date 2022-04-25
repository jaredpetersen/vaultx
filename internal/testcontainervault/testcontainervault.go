// Package testcontainervault is an internal testing utility that aids in setting up a Vault container.
package testcontainervault

import (
	"context"
	"fmt"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Container is a testcontainers-go container for Vault.
type Container struct {
	testcontainers.Container
	URI   string
	Token string
}

// NewContainer starts a new Vault container in dev mode using testcontainers-go.
func NewContainer(ctx context.Context) (*Container, error) {
	rootToken := "root"
	req := testcontainers.ContainerRequest{
		Image:        "vault:1.9.4",
		ExposedPorts: []string{"8200"},
		WaitingFor:   wait.ForHTTP("/v1/sys/health").WithPort("8200/tcp"),
		Env: map[string]string{
			"VAULT_DEV_ROOT_TOKEN_ID": rootToken,
			"VAULT_TOKEN":             rootToken,
			"VAULT_ADDR":              "http://0.0.0.0:8200",
		},
		SkipReaper: true,
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	mappedPort, err := container.MappedPort(ctx, "8200/tcp")
	if err != nil {
		return nil, err
	}

	hostIP, err := container.Host(ctx)
	if err != nil {
		return nil, err
	}

	uri := fmt.Sprintf("http://%s:%s", hostIP, mappedPort.Port())

	return &Container{Container: container, URI: uri, Token: rootToken}, nil
}

// EnableTransit enables the transit engine.
func (c *Container) EnableTransit(ctx context.Context) error {
	cmd := []string{"vault", "secrets", "enable", "transit"}
	_, err := c.Exec(ctx, cmd)
	return err
}

// CreateTransitKey creates a transit key.
func (c *Container) CreateTransitKey(ctx context.Context, transitKey string) error {
	cmd := []string{"vault", "write", "-f", "transit/keys/" + transitKey}
	_, err := c.Exec(ctx, cmd)
	return err
}

// EnableDBEngine enables the database engine.
func (c *Container) EnableDBEngine(ctx context.Context) error {
	cmd := []string{"vault", "secrets", "enable", "database"}
	_, err := c.Exec(ctx, cmd)
	return err
}

// CreateDBEngineRole creates a database engine role for a Postgres database.
func (c *Container) CreateDBEngineRole(ctx context.Context, roleName string, dbName string) error {
	roleCreationStatements := "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; " +
		"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
	cmd := []string{
		"vault",
		"write",
		fmt.Sprintf("database/roles/%s", roleName),
		fmt.Sprintf("db_name=%s", dbName),
		fmt.Sprintf("creation_statements=%s", roleCreationStatements),
		"default_ttl=5m",
		"max_ttl=10m",
	}
	code, err := c.Exec(ctx, cmd)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("failed to create db engine role due to status code %d", code)
	}
	return nil
}

// CreateDBEngineConfig creates a database engine config for a Postgres database.
func (c *Container) CreateDBEngineConfig(ctx context.Context, name string, dbURITemplate string, username string, password string, role string) error {
	cmd := []string{
		"vault",
		"write",
		fmt.Sprintf("database/config/%s", name),
		"plugin_name=postgresql-database-plugin",
		fmt.Sprintf("allowed_roles=%s", role),
		fmt.Sprintf("connection_url=%s", dbURITemplate),
		fmt.Sprintf("username=%s", username),
		fmt.Sprintf("password=%s", password),
	}
	code, err := c.Exec(ctx, cmd)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("failed to create db engine config due to status code %d", code)
	}
	return nil
}
