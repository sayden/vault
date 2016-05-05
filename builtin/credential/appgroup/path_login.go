package appgroup

import (
	"log"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"user_id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "",
				Description: "UserID of the App.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathLoginUpdate,
		},
		HelpSynopsis:    pathLoginHelpSys,
		HelpDescription: pathLoginHelpDesc,
	}
}

func (b *backend) pathLoginRenew(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("pathLoginRenew entered\n")
	return nil, nil
}

func (b *backend) pathLoginUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	userID := data.Get("user_id").(string)
	if userID == "" {
		return logical.ErrorResponse("user_id"), nil
	}
	b.validateUserID(req.Storage, userID)
	return nil, nil
}

const pathLoginHelpSys = `
`

const pathLoginHelpDesc = `
`
