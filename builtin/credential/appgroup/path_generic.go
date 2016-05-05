package appgroup

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type genericStorageEntry struct {
	Groups             []string      `json:"groups" structs:"groups" mapstructure:"groups"`
	Apps               []string      `json:"apps" structs:"apps" mapstructure:"apps"`
	NumUses            int           `json:"num_uses" structs:"num_uses" mapstructure:"num_uses"`
	TTL                time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	MaxTTL             time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
	Wrapped            time.Duration `json:"wrapped" structs:"wrapped" mapstructure:"wrapped"`
	HMACKey            string        `json:"hmac_key" structs:"hmac_key" mapstructure:"hmac_key"`
	AdditionalPolicies []string      `json:"additional_policies" structs:"additional_policies" mapstructure:"additional_policies"`
}

func genericPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "generic/creds$",
			Fields: map[string]*framework.FieldSchema{
				"groups": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "",
					Description: "Comma separated list of Groups.",
				},
				"apps": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "",
					Description: "Comma separated list of Apps.",
				},
				"additional_policies": &framework.FieldSchema{
					Type:    framework.TypeString,
					Default: "",
					Description: `Comma separated list of policies for the Group. The UserID created against the Group,
will have access to the union of all the policies of the Apps. In
addition to those, a set of policies can be assigned using this.
`,
				},
				"num_uses": &framework.FieldSchema{
					Type:        framework.TypeInt,
					Description: "Number of times the a UserID can access the Apps represented by the Group.",
				},
				"ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which a UserID should expire.",
				},
				"max_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "MaxTTL of the UserID created on the App.",
				},
				"wrapped": &framework.FieldSchema{
					Type: framework.TypeDurationSecond,
					Description: `Duration in seconds, if specified, enables Cubbyhole mode. In this mode, a
UserID will not be returned. Instead a new token will be returned. This token
will have the UserID stored in its Cubbyhole. The value represented by 'wrapped'
will be the duration after which the returned token expires.
`,
				},
				"user_id": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "",
					Description: "NOT USER SUPPLIED. UNDOCUMENTED.",
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathGenericCredsUpdate,
			},
			HelpSynopsis:    pathGenericCredsHelpSys,
			HelpDescription: pathGenericCredsHelpDesc,
		},
		&framework.Path{
			Pattern: "generic/creds-specific$",
			Fields: map[string]*framework.FieldSchema{
				"user_id": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "UserID of the App.",
				},
				"groups": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Comma separated list of Groups.",
				},
				"apps": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Comma separated list of Apps.",
				},
				"additional_policies": &framework.FieldSchema{
					Type: framework.TypeString,
					Description: `Comma separated list of policies for the Group. The UserID created against the Group,
will have access to the union of all the policies of the Apps. In
addition to those, a set of policies can be assigned using this.
`,
				},
				"num_uses": &framework.FieldSchema{
					Type:        framework.TypeInt,
					Description: "Number of times the a UserID can access the Apps represented by the Group.",
				},
				"ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which a UserID should expire.",
				},
				"max_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "MaxTTL of the UserID created on the App.",
				},
				"wrapped": &framework.FieldSchema{
					Type: framework.TypeDurationSecond,
					Description: `Duration in seconds, if specified, enables Cubbyhole mode. In this mode, a
UserID will not be returned. Instead a new token will be returned. This token
will have the UserID stored in its Cubbyhole. The value represented by 'wrapped'
will be the duration after which the returned token expires.
`,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathGenericCredsSpecificUpdate,
			},
			HelpSynopsis:    pathGenericCredsSpecificHelpSys,
			HelpDescription: pathGenericCredsSpecificHelpDesc,
		},
	}
}

func setGenericEntry(s logical.Storage, genericName string, generic *genericStorageEntry) error {
	if entry, err := logical.StorageEntryJSON("generic/"+strings.ToLower(genericName), generic); err != nil {
		return err
	} else {
		return s.Put(entry)
	}
}

func genericEntry(s logical.Storage, genericName string) (*genericStorageEntry, error) {
	if genericName == "" {
		return nil, fmt.Errorf("missing generic_name")
	}

	var result genericStorageEntry

	if entry, err := s.Get("generic/" + strings.ToLower(genericName)); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) pathGenericCredsUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	userID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UserID:%s", err)
	}
	data.Raw["user_id"] = userID
	return b.handleGenericCredsCommon(req, data)
}

func (b *backend) pathGenericCredsSpecificUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.handleGenericCredsCommon(req, data)
}

func (b *backend) handleGenericCredsCommon(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	generic := &genericStorageEntry{
		Groups:             strutil.ParseStrings(data.Get("groups").(string)),
		Apps:               strutil.ParseStrings(data.Get("apps").(string)),
		AdditionalPolicies: policyutil.ParsePolicies(data.Get("additional_policies").(string)),
		NumUses:            data.Get("num_uses").(int),
		TTL:                time.Duration(data.Get("ttl").(int)) * time.Second,
		MaxTTL:             time.Duration(data.Get("max_ttl").(int)) * time.Second,
		Wrapped:            time.Duration(data.Get("wrapped").(int)) * time.Second,
	}

	genericName, err := randomName()
	if err != nil {
		return nil, fmt.Errorf("failed to generate a name for generic entry")
	}

	// Store the entry.
	return nil, setGenericEntry(req.Storage, genericName, generic)
}

// Create a random name for generic entry.
func randomName() (string, error) {
	if uuidBytes, err := uuid.GenerateRandomBytes(8); err != nil {
		return "", err
	} else {
		return base64.StdEncoding.EncodeToString(uuidBytes), nil
	}
}

const pathGenericCredsSpecificHelpSys = `
`

const pathGenericCredsSpecificHelpDesc = `
`

const pathGenericCredsHelpSys = `
`

const pathGenericCredsHelpDesc = `
`
