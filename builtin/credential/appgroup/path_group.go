package appgroup

import (
	"log"
	"strings"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type GroupEntry struct {
	GroupName          string        `json:"group_name" structs:"group_name" mapstructure:"group_name"`
	AppNames           []string      `json:"app_names" structs:"app_names" mapstructure:"app_names"`
	AdditionalPolicies []string      `json:"additional_policies" structs:"additional_policies" mapstructure:"additional_policies"`
	NumUses            int           `json:"num_uses" structs:"num_uses" mapstructure:"num_uses"`
	TTL                time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	MaxTTL             time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
	Wrapped            time.Duration `json:"wrapped" structs:"wrapped" mapstructure:"wrapped"`
}

func groupPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name"),
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
				"additional_policies": &framework.FieldSchema{
					Type: framework.TypeString,
					Description: `Comma separated list of policies for the Group. The UserID created against the Group,
will have access to the union of all the policies of the Apps. In
addition to those, a set of policies can be assigned using this.
`,
				},
				"num-uses": &framework.FieldSchema{
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
				logical.CreateOperation: b.pathGroupCreateUpdate,
				logical.UpdateOperation: b.pathGroupCreateUpdate,
				logical.ReadOperation:   b.pathGroupRead,
				logical.DeleteOperation: b.pathGroupDelete,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/policies$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
				"policies": &framework.FieldSchema{
					Type: framework.TypeString,
					Description: `(Addtional) Comma separated list of policies for the Group. The UserID created against the Group,
will have access to the union of all the policies of the Apps. In
addition to those, a set of policies can be assigned using this parameter.
`,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathGroupPoliciesUpdate,
				logical.ReadOperation:   b.pathGroupPoliciesRead,
				logical.DeleteOperation: b.pathGroupPoliciesDelete,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-policies"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-policies"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/num-uses$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
				"num-uses": &framework.FieldSchema{
					Type:        framework.TypeInt,
					Description: "Number of times the a UserID can access the Apps represented by the Group.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathGroupNumUsesUpdate,
				logical.ReadOperation:   b.pathGroupNumUsesRead,
				logical.DeleteOperation: b.pathGroupNumUsesDelete,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-num-uses"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-num-uses"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/ttl$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
				"ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which a UserID should expire.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathGroupTTLUpdate,
				logical.ReadOperation:   b.pathGroupTTLRead,
				logical.DeleteOperation: b.pathGroupTTLDelete,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-ttl"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-ttl"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/max-ttl$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
				"max_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "MaxTTL of the UserID created on the App.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathGroupMaxTTLUpdate,
				logical.ReadOperation:   b.pathGroupMaxTTLRead,
				logical.DeleteOperation: b.pathGroupMaxTTLDelete,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-max-ttl"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-max-ttl"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/wrapped$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
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
				logical.UpdateOperation: b.pathGroupWrappedUpdate,
				logical.ReadOperation:   b.pathGroupWrappedRead,
				logical.DeleteOperation: b.pathGroupWrappedDelete,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-wrapped"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-wrapped"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/creds$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathGroupCredsRead,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-creds"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-creds"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/creds-specific$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
				"user_id": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "UserID to be attached to the App.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathGroupCredsSpecificUpdate,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-creds-specific"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-creds-specific"][1]),
		},
	}
}

func (b *backend) pathGroupCreateUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathGroupCreateUpdate entered\n")
	return nil, nil
}

func (b *backend) pathGroupRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathGroupCreateUpdate entered\n")
	return nil, nil
}

func (b *backend) pathGroupDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathGroupDelete entered\n")
	return nil, nil
}

func (b *backend) pathGroupPoliciesUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathGroupPoliciesUpdate entered\n")
	return nil, nil
}

func (b *backend) pathGroupPoliciesRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathGroupPoliciesRead entered\n")
	return nil, nil
}

func (b *backend) pathGroupPoliciesDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathGroupPoliciesDelete entered\n")
	return nil, nil
}

func (b *backend) pathGroupNumUsesUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathGroupNumUsesUpdate entered\n")
	return nil, nil
}

func (b *backend) pathGroupNumUsesRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathGroupNumUsesRead entered\n")
	return nil, nil
}

func (b *backend) pathGroupNumUsesDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathGroupNumUsesDelete entered\n")
	return nil, nil
}

func (b *backend) pathGroupTTLUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathGroupTTLUpdate entered\n")
	return nil, nil
}

func (b *backend) pathGroupTTLRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathGroupTTLRead entered\n")
	return nil, nil
}

func (b *backend) pathGroupTTLDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathGroupTTLDelete entered\n")
	return nil, nil
}

func (b *backend) pathGroupMaxTTLUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathGroupTTLUpdate entered\n")
	return nil, nil
}

func (b *backend) pathGroupMaxTTLRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathGroupTTLRead entered\n")
	return nil, nil
}

func (b *backend) pathGroupMaxTTLDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathGroupTTLDelete entered\n")
	return nil, nil
}

func (b *backend) pathGroupWrappedUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathGroupWrappedUpdate entered\n")
	return nil, nil
}

func (b *backend) pathGroupWrappedRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathGroupWrappedRead entered\n")
	return nil, nil
}

func (b *backend) pathGroupWrappedDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathGroupWrappedDelete entered\n")
	return nil, nil
}

func (b *backend) pathGroupCredsRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathGroupCredsRead entered\n")
	return nil, nil
}

func (b *backend) pathGroupCredsSpecificUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathGroupCredsSpecificUpdate entered\n")
	return nil, nil
}

var groupHelp = map[string][2]string{
	"group":                {"help", "desc"},
	"group-policies":       {"help", "desc"},
	"group-num-uses":       {"help", "desc"},
	"group-ttl":            {"help", "desc"},
	"group-max-ttl":        {"help", "desc"},
	"group-wrgrouped":      {"help", "desc"},
	"group-creds":          {"help", "desc"},
	"group-creds-specific": {"help", "desc"},
}
