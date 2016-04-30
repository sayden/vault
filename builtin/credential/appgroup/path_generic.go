package appgroup

import (
	"log"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func genericPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "generic/creds$",
			Fields: map[string]*framework.FieldSchema{
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
				logical.UpdateOperation: b.pathGenericCredsSpecificUpdate,
			},
			HelpSynopsis:    pathGenericCredsSpecificHelpSys,
			HelpDescription: pathGenericCredsSpecificHelpDesc,
		},
	}
}

func (b *backend) pathGenericCredsUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathGenericCredsRead entered\n")
	return nil, nil
}

func (b *backend) pathGenericCredsSpecificUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathGenericCredsSpecificUpdate entered\n")
	return nil, nil
}

const pathGenericCredsSpecificHelpSys = `
`

const pathGenericCredsSpecificHelpDesc = `
`

const pathGenericCredsHelpSys = `
`

const pathGenericCredsHelpDesc = `
`
