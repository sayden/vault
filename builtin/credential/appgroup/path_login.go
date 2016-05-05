package appgroup

import (
	"fmt"
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
	parseResp, err := b.parseAndVerifyUserID(req.Storage, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse and verify user ID: %s", err)
	}

	if parseResp == nil ||
		!parseResp.Verified ||
		parseResp.SelectorType == "" ||
		parseResp.SelectorValue == "" {
		return nil, fmt.Errorf("failed to parse and verify user ID")
	}

	resp := &logical.Response{
		Auth: &logical.Auth{
			LeaseOptions: logical.LeaseOptions{
				Renewable: true,
			},
		},
	}

	switch parseResp.SelectorType {
	case selectorTypeApp:
		app, err := appEntry(req.Storage, parseResp.SelectorValue)
		if err != nil {
			return nil, err
		}
		if app == nil {
			return nil, fmt.Errorf("app referred by the user ID does not exist")
		}
		resp.Auth.Policies = app.Policies
		resp.Auth.LeaseOptions.TTL = app.TTL
	case selectorTypeGroup:
		group, err := groupEntry(req.Storage, parseResp.SelectorValue)
		if err != nil {
			return nil, err
		}
		if group == nil {
			return nil, fmt.Errorf("group referred by the user ID does not exist")
		}
		resp.Auth.Policies = group.AdditionalPolicies
		resp.Auth.LeaseOptions.TTL = group.TTL
	case selectorTypeGeneric:
	default:
		return nil, fmt.Errorf("unknown selector type")
	}

	return resp, nil
}

const pathLoginHelpSys = `
`

const pathLoginHelpDesc = `
`
