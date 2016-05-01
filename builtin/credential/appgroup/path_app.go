package appgroup

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/fatih/structs"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type appStorageEntry struct {
	Policies []string      `json:"policies" structs:"policies" mapstructure:"policies"`
	NumUses  int           `json:"num_uses" structs:"num_uses" mapstructure:"num_uses"`
	TTL      time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	MaxTTL   time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
	Wrapped  time.Duration `json:"wrapped" structs:"wrapped" mapstructure:"wrapped"`
}

func appPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name"),
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"policies": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "default",
					Description: "Comma separated list of policies on the App.",
				},
				"num_uses": &framework.FieldSchema{
					Type:        framework.TypeInt,
					Description: "Number of times the a UserID can access the App.",
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
				logical.CreateOperation: b.pathAppCreateUpdate,
				logical.UpdateOperation: b.pathAppCreateUpdate,
				logical.ReadOperation:   b.pathAppRead,
				logical.DeleteOperation: b.pathAppDelete,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app"][1]),
		},
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/policies$",
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"policies": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "",
					Description: "Comma separated list of policies on the App.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathAppPoliciesUpdate,
				logical.ReadOperation:   b.pathAppPoliciesRead,
				logical.DeleteOperation: b.pathAppPoliciesDelete,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-policies"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-policies"][1]),
		},
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/num-uses$",
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"num-uses": &framework.FieldSchema{
					Type:        framework.TypeInt,
					Description: "Number of times the a UserID can access the App.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathAppNumUsesUpdate,
				logical.ReadOperation:   b.pathAppNumUsesRead,
				logical.DeleteOperation: b.pathAppNumUsesDelete,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-num-uses"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-num-uses"][1]),
		},
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/ttl$",
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which a UserID should expire.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathAppTTLUpdate,
				logical.ReadOperation:   b.pathAppTTLRead,
				logical.DeleteOperation: b.pathAppTTLDelete,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-ttl"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-ttl"][1]),
		},
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/max-ttl$",
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"max_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "MaxTTL of the UserID created on the App.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathAppMaxTTLUpdate,
				logical.ReadOperation:   b.pathAppMaxTTLRead,
				logical.DeleteOperation: b.pathAppMaxTTLDelete,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-max-ttl"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-max-ttl"][1]),
		},
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/wrapped$",
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
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
				logical.UpdateOperation: b.pathAppWrappedUpdate,
				logical.ReadOperation:   b.pathAppWrappedRead,
				logical.DeleteOperation: b.pathAppWrappedDelete,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-wrapped"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-wrapped"][1]),
		},
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/creds$",
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"user_id": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "",
					Description: "NOT USER SUPPLIED",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathAppCredsRead,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-creds"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-creds"][1]),
		},
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/creds-specific$",
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"user_id": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "",
					Description: "UserID to be attached to the App.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathAppCredsSpecificUpdate,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-creds-specified"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-creds-specified"][1]),
		},
	}
}

func setAppEntry(s logical.Storage, appName string, app *appStorageEntry) error {
	if entry, err := logical.StorageEntryJSON("app/"+strings.ToLower(appName), app); err != nil {
		return err
	} else {
		return s.Put(entry)
	}
}

func appEntry(s logical.Storage, appName string) (*appStorageEntry, error) {
	if appName == "" {
		return nil, fmt.Errorf("missing app_name")
	}

	var result appStorageEntry

	if entry, err := s.Get("app/" + strings.ToLower(appName)); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) pathAppCreateUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	// Check if there is already an entry. If entry exists, this is an
	// UpdateOperation.
	app, err := appEntry(req.Storage, appName)
	if err != nil {
		return nil, err
	}

	// If entry does not exist, this is a CreateOperation. So, create
	// a new object.
	if app == nil {
		app = &appStorageEntry{}
	}

	if policiesRaw, ok := data.GetOk("policies"); ok {
		app.Policies = policyutil.ParsePolicies(policiesRaw.(string))
	} else if req.Operation == logical.CreateOperation {
		app.Policies = policyutil.ParsePolicies(data.Get("policies").(string))
	}

	// Update only if value is supplied. Defaults to zero.
	if numUsesRaw, ok := data.GetOk("num_uses"); ok {
		app.NumUses = numUsesRaw.(int)
	}

	// If TTL value is not provided either during update or create, don't bother.
	// Core will set the system default value if the policies does not contain
	// "root" and TTL value is zero.
	// Update only if value is supplied. Defaults to zero.
	if ttlRaw, ok := data.GetOk("ttl"); ok {
		app.TTL = time.Duration(ttlRaw.(int)) * time.Second
	}

	// Update only if value is supplied. Defaults to zero.
	if maxTTLRaw, ok := data.GetOk("max_ttl"); ok {
		app.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	}

	// Check that TTL value provided is greater than MaxTTL.
	//
	// Do not sanitize the TTL and MaxTTL now, just store them as-is.
	// Check the System TTL and MaxTTL values at credential issue time
	// and act accordingly.
	if app.TTL > app.MaxTTL {
		return logical.ErrorResponse("ttl should not be greater than max_ttl"), nil
	}

	// Update only if value is supplied. Defaults to zero.
	if wrappedRaw, ok := data.GetOk("wrapped"); ok {
		app.Wrapped = time.Duration(wrappedRaw.(int)) * time.Second
	}

	// Store the entry.
	return nil, setAppEntry(req.Storage, appName, app)
}

func (b *backend) pathAppRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := appEntry(req.Storage, strings.ToLower(appName)); err != nil {
		return nil, err
	} else if app == nil {
		return nil, nil
	} else {
		// Convert the values to second
		app.TTL = app.TTL / time.Second
		app.MaxTTL = app.MaxTTL / time.Second
		app.Wrapped = app.Wrapped / time.Second

		return &logical.Response{
			Data: structs.New(app).Map(),
		}, nil
	}
}

func (b *backend) pathAppDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	return nil, req.Storage.Delete("app/" + strings.ToLower(appName))
}

func (b *backend) pathAppPoliciesUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	if policiesRaw, ok := data.GetOk("policies"); ok {
		app.Policies = policyutil.ParsePolicies(policiesRaw.(string))
		return nil, setAppEntry(req.Storage, appName, app)
	} else {
		return logical.ErrorResponse("missing policies"), nil
	}
}

func (b *backend) pathAppPoliciesRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := appEntry(req.Storage, strings.ToLower(appName)); err != nil {
		return nil, err
	} else if app == nil {
		return nil, nil
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"policies": app.Policies,
			},
		}, nil
	}
}

func (b *backend) pathAppPoliciesDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	app.Policies = (&appStorageEntry{}).Policies

	return nil, setAppEntry(req.Storage, appName, app)
}

func (b *backend) pathAppNumUsesUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	if numUsesRaw, ok := data.GetOk("num_uses"); ok {
		app.NumUses = numUsesRaw.(int)
		return nil, setAppEntry(req.Storage, appName, app)
	} else {
		return logical.ErrorResponse("missing num_uses"), nil
	}
}

func (b *backend) pathAppNumUsesRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := appEntry(req.Storage, strings.ToLower(appName)); err != nil {
		return nil, err
	} else if app == nil {
		return nil, nil
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"num_uses": app.NumUses,
			},
		}, nil
	}
}

func (b *backend) pathAppNumUsesDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	app.NumUses = (&appStorageEntry{}).NumUses

	return nil, setAppEntry(req.Storage, appName, app)
}

func (b *backend) pathAppTTLUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	if ttlRaw, ok := data.GetOk("ttl"); ok {
		if app.TTL = time.Duration(ttlRaw.(int)) * time.Second; app.TTL > app.MaxTTL {
			return logical.ErrorResponse("ttl should not be greater than max_ttl"), nil
		}
		return nil, setAppEntry(req.Storage, appName, app)
	} else {
		return logical.ErrorResponse("missing ttl"), nil
	}
}

func (b *backend) pathAppTTLRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := appEntry(req.Storage, strings.ToLower(appName)); err != nil {
		return nil, err
	} else if app == nil {
		return nil, nil
	} else {
		app.TTL = app.TTL / time.Second
		return &logical.Response{
			Data: map[string]interface{}{
				"ttl": app.TTL,
			},
		}, nil
	}
}

func (b *backend) pathAppTTLDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	app.TTL = (&appStorageEntry{}).TTL

	return nil, setAppEntry(req.Storage, appName, app)
}

func (b *backend) pathAppMaxTTLUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	if maxTTLRaw, ok := data.GetOk("max_ttl"); ok {
		if app.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second; app.TTL > app.MaxTTL {
			return logical.ErrorResponse("max_ttl should be greater than ttl"), nil
		}
		return nil, setAppEntry(req.Storage, appName, app)
	} else {
		return logical.ErrorResponse("missing max_ttl"), nil
	}
}

func (b *backend) pathAppMaxTTLRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := appEntry(req.Storage, strings.ToLower(appName)); err != nil {
		return nil, err
	} else if app == nil {
		return nil, nil
	} else {
		app.MaxTTL = app.MaxTTL / time.Second
		return &logical.Response{
			Data: map[string]interface{}{
				"max_ttl": app.MaxTTL,
			},
		}, nil
	}
}

func (b *backend) pathAppMaxTTLDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	app.MaxTTL = (&appStorageEntry{}).MaxTTL

	return nil, setAppEntry(req.Storage, appName, app)
}

func (b *backend) pathAppWrappedUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	if wrappedRaw, ok := data.GetOk("wrapped"); ok {
		app.Wrapped = time.Duration(wrappedRaw.(int)) * time.Second
		return nil, setAppEntry(req.Storage, appName, app)
	} else {
		return logical.ErrorResponse("missing wrapped"), nil
	}
}

func (b *backend) pathAppWrappedRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := appEntry(req.Storage, strings.ToLower(appName)); err != nil {
		return nil, err
	} else if app == nil {
		return nil, nil
	} else {
		app.Wrapped = app.Wrapped / time.Second
		return &logical.Response{
			Data: map[string]interface{}{
				"wrapped": app.Wrapped,
			},
		}, nil
	}
}

func (b *backend) pathAppWrappedDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	app.Wrapped = (&appStorageEntry{}).Wrapped

	return nil, setAppEntry(req.Storage, appName, app)
}

func (b *backend) pathAppCredsRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	userID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UserID:%s", err)
	}
	data.Raw["user_id"] = userID
	return handleAppCredsCommon(req, data)
}

func (b *backend) pathAppCredsSpecificUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return handleAppCredsCommon(req, data)
}

func handleAppCredsCommon(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("handleAppCredsCommon entered\n")
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return logical.ErrorResponse(fmt.Sprintf("App %s does not exist", appName)), nil
	}
	log.Printf("creds: app: %#v\n", app)
	return nil, nil
}

var appHelp = map[string][2]string{
	"app":                {"help", "desc"},
	"app-policies":       {"help", "desc"},
	"app-num-uses":       {"help", "desc"},
	"app-ttl":            {"help", "desc"},
	"app-max-ttl":        {"help", "desc"},
	"app-wrapped":        {"help", "desc"},
	"app-creds":          {"help", "desc"},
	"app-creds-specific": {"help", "desc"},
}
