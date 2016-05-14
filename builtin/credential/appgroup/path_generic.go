package appgroup

import (
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
	UserIDTTL          time.Duration `json:"userid_ttl" structs:"userid_ttl" mapstructure:"userid_ttl"`
	TokenTTL           time.Duration `json:"token_ttl" structs:"token_ttl" mapstructure:"token_ttl"`
	TokenMaxTTL        time.Duration `json:"token_max_ttl" structs:"token_max_ttl" mapstructure:"token_max_ttl"`
	Wrapped            time.Duration `json:"wrapped" structs:"wrapped" mapstructure:"wrapped"`
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
				"userid_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued UserID should expire.",
				},
				"token_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued token should expire.",
				},
				"token_max_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued token should not be allowed to be renewed.",
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
				"userid_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued UserID should expire.",
				},
				"token_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued token should expire.",
				},
				"token_max_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued token should not be allowed to be renewed.",
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

func (b *backend) setGenericEntry(s logical.Storage, genericName string, generic *genericStorageEntry) error {
	b.genericLock.Lock()
	defer b.genericLock.Unlock()
	if entry, err := logical.StorageEntryJSON("generic/"+strings.ToLower(genericName), generic); err != nil {
		return err
	} else {
		return s.Put(entry)
	}
}

func (b *backend) deleteGenericEntry(s logical.Storage, genericName string) error {
	if genericName == "" {
		return fmt.Errorf("missing generic_name")
	}

	return s.Delete("generic/" + strings.ToLower(genericName))
}

func (b *backend) genericEntry(s logical.Storage, genericName string) (*genericStorageEntry, error) {
	if genericName == "" {
		return nil, fmt.Errorf("missing generic_name")
	}

	var result genericStorageEntry

	b.genericLock.RLock()
	defer b.genericLock.RUnlock()

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
	return b.handleGenericCredsCommon(req, data, false)
}

func (b *backend) pathGenericCredsSpecificUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.handleGenericCredsCommon(req, data, true)
}

func (b *backend) handleGenericCredsCommon(req *logical.Request, data *framework.FieldData, specified bool) (*logical.Response, error) {
	generic := &genericStorageEntry{
		Groups:             strutil.ParseStrings(data.Get("groups").(string)),
		Apps:               strutil.ParseStrings(data.Get("apps").(string)),
		AdditionalPolicies: policyutil.ParsePolicies(data.Get("additional_policies").(string)),
		NumUses:            data.Get("num_uses").(int),
		UserIDTTL:          time.Second * time.Duration(data.Get("userid_ttl").(int)),
		TokenTTL:           time.Second * time.Duration(data.Get("token_ttl").(int)),
		TokenMaxTTL:        time.Second * time.Duration(data.Get("token_max_ttl").(int)),
		Wrapped:            time.Second * time.Duration(data.Get("wrapped").(int)),
	}

	if len(generic.Groups) == 0 && len(generic.Apps) == 0 {
		return logical.ErrorResponse("missing groups and/or apps"), nil
	}

	if generic.NumUses < 0 {
		return logical.ErrorResponse("num_uses cannot be negative"), nil
	}

	if generic.TokenTTL > generic.TokenMaxTTL {
		return logical.ErrorResponse("token_ttl should not be greater than token_max_ttl"), nil
	}

	userID := data.Get("user_id").(string)
	if userID == "" {
		return logical.ErrorResponse("missing user_id"), nil
	}

	genericName := b.salt.SaltID(userID)

	// Store the entry.
	if err := b.setGenericEntry(req.Storage, genericName, generic); err != nil {
		return nil, err
	}

	if err := b.registerUserIDEntry(req.Storage, selectorTypeGeneric, genericName, userID, &userIDStorageEntry{
		NumUses: generic.NumUses,
	}); err != nil {
		return nil, fmt.Errorf("failed to store user ID: %s", err)
	}

	if specified {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"user_id": userID,
		},
	}, nil
}

const pathGenericCredsSpecificHelpSys = `
`

const pathGenericCredsSpecificHelpDesc = `
`

const pathGenericCredsHelpSys = `
`

const pathGenericCredsHelpDesc = `
`
