package appgroup

import (
	"sync"

	"github.com/hashicorp/vault/helper/salt"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type backend struct {
	*framework.Backend
	salt *salt.Salt

	// Guard to clean-up the expired UserID entries
	tidyUserIDCASGuard uint32

	// Lock to make changes to registered Apps
	appLock *sync.RWMutex

	// Lock to make changes to registered Apps
	groupLock *sync.RWMutex

	// Lock to make changes to "generic" mode storage entries
	genericLock *sync.RWMutex

	// Map of locks to make changes to the UserIDs created.
	// The lock in the map will be keyed off of UserID itself.
	// Each UserID will have a separate lock which is used to
	// update the information related to it, 'num_uses' for example.
	// The lock will be deleted when the UserID is delted.
	userIDLocksMap map[string]*sync.RWMutex

	// Guard to access the map containing locks to manage UserID storage entries
	userIDLocksMapGuard uint32
}

func Factory(conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := Backend(conf)
	if err != nil {
		return nil, err
	}
	return b.Setup(conf)
}

func Backend(conf *logical.BackendConfig) (*framework.Backend, error) {
	// Initialize the salt
	salt, err := salt.NewSalt(conf.StorageView, &salt.Config{
		HashFunc: salt.SHA256Hash,
	})
	if err != nil {
		return nil, err
	}

	// Create a backend object
	b := &backend{
		// Set the salt object for the backend
		salt: salt,

		// Create the lock for making changes to the Apps registered with the backend
		appLock: &sync.RWMutex{},

		// Create the lock for making changes to the Groups registered with the backend
		groupLock: &sync.RWMutex{},

		// Create the lock for making changes to the storage entries of "generic" mode
		genericLock: &sync.RWMutex{},

		// Create the map of locks to hold locks that are used to modify the created
		// UserIDs.
		userIDLocksMap: map[string]*sync.RWMutex{},
	}

	// Attach the paths and secrets that are to be handled by the backend
	b.Backend = &framework.Backend{
		// Register a periodic function that deletes the expired UserID entries
		PeriodicFunc: b.periodicFunc,
		Help:         backendHelp,
		AuthRenew:    b.pathLoginRenew,
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
				pathTidyUserID(b),
			},
		),
	}
	return b.Backend, nil
}

// periodicFunc of the backend will be invoked once a minute by the RollbackManager.
// AppGroup backend utilizes this function to delete expired UserID entries.
// This could mean that the UserID may live in the backend upto 1min after its
// expiration. The deletion of UserIDs are not security sensitive and it is okay
// to delay the removal of UserIDs by a minute.
func (b *backend) periodicFunc(req *logical.Request) error {
	// Initiate clean-up of expired UserID entries
	b.tidyUserID(req.Storage)
	return nil
}

const backendHelp = `Any registered App(s) or Group(s) of Apps can authenticate themselves
with Vault using UserIDs that are specifically generated to serve that
purpose. The UserIDs have nice properties like usage-limit and expiration,
that can address numerous use-cases. An App can represent a service, or
a machine or anything that can be IDed. Since an App can be a machine in
itself, the AppGroup backend is a potential successor for the App-ID backend.`
