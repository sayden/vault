package appgroup

import (
	"time"

	"github.com/hashicorp/vault/helper/salt"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type UserIDType int

const (
	AppUserID UserIDType = iota
	GroupUserID
	GenericUserID
)

type UserID struct {
	Type     UserIDType    `json:"type" structs:"type" mapstructure:"type"`
	AppNames []string      `json:"app_name" structs:"app_name" mapstructure:"app_name"`
	Policies []string      `json:"policies" structs:"policies" mapstructure:"policies"`
	TTL      time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	MaxTTL   time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
	Wrapped  time.Duration `json:"wrapped" structs:"wrapped" mapstructure:"wrapped"`
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
		Salt: salt,
	}

	// Attach the endpoints that are to be handled by the backend
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
	return b.Backend, nil
}

type backend struct {
	*framework.Backend
	Salt *salt.Salt
}

const backendHelp = `
`
