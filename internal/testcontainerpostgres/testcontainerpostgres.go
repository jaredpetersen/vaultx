// Package testcontainerpostgres is an internal testing utility that aids in setting up a Postgres container.
package testcontainerpostgres

import (
	"context"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Container is a testcontainers-go container for Postgres.
type Container struct {
	testcontainers.Container
}

// NewContainer starts a new Postgres container using testcontainers-go.
func NewContainer(ctx context.Context, user string, password string, db string) (*Container, error) {
	req := testcontainers.ContainerRequest{
		Image:        "postgres:14",
		ExposedPorts: []string{"5432"},
		Env: map[string]string{
			"POSTGRES_USER":     user,
			"POSTGRES_PASSWORD": password,
			"POSTGRES_DB":       db,
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections"),
		SkipReaper: true,
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	return &Container{Container: container}, nil
}
