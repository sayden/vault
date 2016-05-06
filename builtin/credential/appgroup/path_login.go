package appgroup

import (
	"fmt"
	"strings"

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
	selectorType := req.Auth.Metadata["selector_type"]
	selectorValue := req.Auth.Metadata["selector_value"]
	if selectorType == "" || selectorValue == "" {
		return nil, fmt.Errorf("failed to fetch selector type and/or selector value during renewal")
	}
	resp, err := b.validateSelector(req.Storage, selectorType, selectorValue)
	if err != nil {
		return nil, fmt.Errorf("failed to validate selector during renewal:%s", err)
	}

	return framework.LeaseExtend(resp.TTL, resp.MaxTTL, b.System())(req, data)
}

func (b *backend) pathLoginUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	userID := data.Get("user_id").(string)
	if userID == "" {
		return logical.ErrorResponse("user_id"), nil
	}
	// Avoid problems with extra spaces introduced while typing in the input by the client.
	userID = strings.TrimSpace(userID)

	validateResp, err := b.validateUserID(req.Storage, userID)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to validate user ID: %s", err)), nil
	}

	resp := &logical.Response{
		Auth: &logical.Auth{
			Metadata: map[string]string{
				"selector_type":  validateResp.SelectorType,
				"selector_value": validateResp.SelectorValue,
			},
			Policies: validateResp.Policies,
			LeaseOptions: logical.LeaseOptions{
				TTL:       validateResp.TTL,
				Renewable: true,
			},
		},
	}
	return resp, nil
}

const pathLoginHelpSys = `
`

const pathLoginHelpDesc = `
`
