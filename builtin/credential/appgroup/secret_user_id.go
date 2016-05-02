package appgroup

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type UserIDType int

const (
	AppUserIDType UserIDType = iota
	GroupUserIDType
	GenericUserIDType
)

const SecretUserIDType = "secret_user_id"

type userIDStorageEntry struct {
	Type     UserIDType    `json:"type" structs:"type" mapstructure:"type"`
	AppNames []string      `json:"app_name" structs:"app_name" mapstructure:"app_name"`
	Policies []string      `json:"policies" structs:"policies" mapstructure:"policies"`
	TTL      time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	MaxTTL   time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
	Wrapped  time.Duration `json:"wrapped" structs:"wrapped" mapstructure:"wrapped"`
}

func (b *backend) setUserIDEntry(s logical.Storage, userIDType UserIDType, userID string, idEntry *appStorageEntry) error {
	if userID == "" {
		return fmt.Errorf("missing userID")
	}

	selector := ""
	switch userIDType {
	case AppUserIDType:
		selector = "app/"
	case GroupUserIDType:
		selector = "group/"
	case GenericUserIDType:
		selector = "generic/"
	default:
		return fmt.Errorf("unknown selector for storing UserID")
	}

	entryIndex := "userid/" + selector + b.salt.SaltID(strings.ToLower(userID))
	log.Printf("storing entryIndex: %s\n", entryIndex)
	if entry, err := logical.StorageEntryJSON(entryIndex, idEntry); err != nil {
		return err
	} else {
		return s.Put(entry)
	}
}

func (b *backend) userIDEntry(s logical.Storage, userIDType UserIDType, userID string) (*userIDStorageEntry, error) {
	if userID == "" {
		return nil, fmt.Errorf("missing userID")
	}

	var result userIDStorageEntry

	selector := ""
	switch userIDType {
	case AppUserIDType:
		selector = "app/"
	case GroupUserIDType:
		selector = "group/"
	case GenericUserIDType:
		selector = "generic/"
	default:
		return nil, fmt.Errorf("unknown selector for reading UserID")
	}

	entryIndex := "userid/" + selector + b.salt.SaltID(strings.ToLower(userID))
	log.Printf("reading entryIndex: %s\n", entryIndex)
	if entry, err := s.Get(entryIndex); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
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
