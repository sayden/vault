package appgroup

import (
	"sync"
	"testing"

	"github.com/hashicorp/vault/helper/salt"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func failOnError(t *testing.T, resp *logical.Response, err error) {
	if resp != nil && resp.IsError() {
		t.Fatalf("error returned in response: %s", resp.Data["error"])
	}
	if err != nil {
		t.Fatal(err)
	}
}

func createBackendWithStorage(t *testing.T) (*backend, *logical.InmemStorage) {
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b, err := createBackend(config)
	if err != nil {
		t.Fatal(err)
	}
	if b == nil {
		t.Fatalf("failed to create backend")
	}
	_, err = b.Backend.Setup(config)
	if err != nil {
		t.Fatal(err)
	}
	return b, storage
}

func createBackend(conf *logical.BackendConfig) (*backend, error) {
	// Initialize the salt
	salt, err := salt.NewSalt(conf.StorageView, &salt.Config{
		HashFunc: salt.SHA256Hash,
	})
	if err != nil {
		return nil, err
	}

	// Create a backend object
	b := &backend{
		salt:        salt,
		appLock:     &sync.RWMutex{},
		groupLock:   &sync.RWMutex{},
		genericLock: &sync.RWMutex{},
		userIDLocks: map[string]*sync.RWMutex{},
	}

	// Attach the paths and secrets that are to be handled by the backend
	b.Backend = &framework.Backend{
		Help:      backendHelp,
		AuthRenew: b.pathLoginRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
		},
		Paths: framework.PathAppend(
			appPaths(b),
			groupPaths(b),
			genericPaths(b),
			[]*framework.Path{
				pathLogin(b),
			},
		),
	}
	return b, nil
}
