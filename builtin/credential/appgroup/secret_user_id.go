package appgroup

import (
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type UserIDType int

const (
	AppUserID UserIDType = iota
	GroupUserID
	GenericUserID
)

const SecretUserIDType = "secret_user_id"

type UserID struct {
	Type     UserIDType    `json:"type" structs:"type" mapstructure:"type"`
	AppNames []string      `json:"app_name" structs:"app_name" mapstructure:"app_name"`
	Policies []string      `json:"policies" structs:"policies" mapstructure:"policies"`
	TTL      time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	MaxTTL   time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
	Wrapped  time.Duration `json:"wrapped" structs:"wrapped" mapstructure:"wrapped"`
}

func secretUserID(b *backend) *framework.Secret {
	return &framework.Secret{
		Revoke: b.secretUserIDRevoke,
		Renew:  b.secretUserIDRenew,
		Type:   SecretUserIDType,
		Fields: map[string]*framework.FieldSchema{
			"apps": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "",
				Description: "Apps that this UserID can access.",
			},
			"policies": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "default",
				Description: "Comma separated list of policies on the UserID.",
			},
			"num_uses": &framework.FieldSchema{
				Type:        framework.TypeInt,
				Description: "Number of times the a UserID can be used.",
			},
			"ttl": &framework.FieldSchema{
				Type:        framework.TypeDurationSecond,
				Description: "Duration in seconds after which this UserID will expire.",
			},
			"max_ttl": &framework.FieldSchema{
				Type:        framework.TypeDurationSecond,
				Description: "MaxTTL of the UserID created.",
			},
			"wrapped": &framework.FieldSchema{
				Type:        framework.TypeDurationSecond,
				Description: "If set, Cubbyhole mode is enabled on the UserID. The value represents the TTL of the encapsulating token.",
			},
		},
	}
}

func (b *backend) secretUserIDRevoke(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

func (b *backend) secretUserIDRenew(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}
