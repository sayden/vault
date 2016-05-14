package appgroup

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/structs"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type appStorageEntry struct {
	Policies    []string      `json:"policies" structs:"policies" mapstructure:"policies"`
	NumUses     int           `json:"num_uses" structs:"num_uses" mapstructure:"num_uses"`
	UserIDTTL   time.Duration `json:"userid_ttl" structs:"userid_ttl" mapstructure:"userid_ttl"`
	TokenTTL    time.Duration `json:"token_ttl" structs:"token_ttl" mapstructure:"token_ttl"`
	TokenMaxTTL time.Duration `json:"token_max_ttl" structs:"token_max_ttl" mapstructure:"token_max_ttl"`
	Wrapped     time.Duration `json:"wrapped" structs:"wrapped" mapstructure:"wrapped"`
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
					Description: "Number of times the a UserID can access the App, after which it will expire.",
				},
				"userid_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Default:     259200, //72h
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
					Description: `Duration in seconds, if specified, enables the Cubbyhole mode. In this mode,
the UserID creation endpoints will not return the UserID directly. Instead,
a new token will be returned with the UserID stored in its Cubbyhole. The
value of 'wrapped' is the duration after which the returned token expires.
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
				"num_uses": &framework.FieldSchema{
					Type:        framework.TypeInt,
					Description: "Number of times the a UserID can access the App, after which it will expire.",
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
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/userid-ttl$",
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"userid_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued UserID should expire.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathAppUserIDTTLUpdate,
				logical.ReadOperation:   b.pathAppUserIDTTLRead,
				logical.DeleteOperation: b.pathAppUserIDTTLDelete,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-userid-ttl"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-userid-ttl"][1]),
		},
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/token-ttl$",
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"token_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued token should expire.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathAppTokenTTLUpdate,
				logical.ReadOperation:   b.pathAppTokenTTLRead,
				logical.DeleteOperation: b.pathAppTokenTTLDelete,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-token-ttl"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-token-ttl"][1]),
		},
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/token-max-ttl$",
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"token_max_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued token should not be allowed to be renewed.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathAppTokenMaxTTLUpdate,
				logical.ReadOperation:   b.pathAppTokenMaxTTLRead,
				logical.DeleteOperation: b.pathAppTokenMaxTTLDelete,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-token-max-ttl"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-token-max-ttl"][1]),
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
					Description: `Duration in seconds, if specified, enables the Cubbyhole mode. In this mode,
the UserID creation endpoints will not return the UserID directly. Instead,
a new token will be returned with the UserID stored in its Cubbyhole. The
value of 'wrapped' is the duration after which the returned token expires.
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
					Description: "NOT USER SUPPLIED AND UNDOCUMENTED.",
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

func (b *backend) setAppEntry(s logical.Storage, appName string, app *appStorageEntry) error {
	b.appLock.Lock()
	defer b.appLock.Unlock()
	if entry, err := logical.StorageEntryJSON("app/"+strings.ToLower(appName), app); err != nil {
		return err
	} else {
		return s.Put(entry)
	}
}

func (b *backend) appEntry(s logical.Storage, appName string) (*appStorageEntry, error) {
	if appName == "" {
		return nil, fmt.Errorf("missing app_name")
	}

	var result appStorageEntry

	b.appLock.RLock()
	defer b.appLock.RUnlock()

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

	// Fetch or create an entry for the app
	app, err := b.appEntry(req.Storage, appName)
	if err != nil {
		return nil, err
	}
	if app == nil {
		app = &appStorageEntry{}
	}

	if policiesRaw, ok := data.GetOk("policies"); ok {
		app.Policies = policyutil.ParsePolicies(policiesRaw.(string))
	} else if req.Operation == logical.CreateOperation {
		app.Policies = policyutil.ParsePolicies(data.Get("policies").(string))
	}

	if numUsesRaw, ok := data.GetOk("num_uses"); ok {
		app.NumUses = numUsesRaw.(int)
	} else if req.Operation == logical.CreateOperation {
		app.NumUses = data.Get("num_uses").(int)
	}
	if app.NumUses < 0 {
		return logical.ErrorResponse("num_uses cannot be negative"), nil
	}

	if userIDTTLRaw, ok := data.GetOk("userid_ttl"); ok {
		app.UserIDTTL = time.Second * time.Duration(userIDTTLRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		app.UserIDTTL = time.Second * time.Duration(data.Get("userid_ttl").(int))
	}

	if tokenTTLRaw, ok := data.GetOk("token_ttl"); ok {
		app.TokenTTL = time.Second * time.Duration(tokenTTLRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		app.TokenTTL = time.Second * time.Duration(data.Get("token_ttl").(int))
	}

	if tokenMaxTTLRaw, ok := data.GetOk("token_max_ttl"); ok {
		app.TokenMaxTTL = time.Second * time.Duration(tokenMaxTTLRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		app.TokenMaxTTL = time.Second * time.Duration(data.Get("token_max_ttl").(int))
	}

	// Check that the TokenMaxTTL value provided is less than the TokenMaxTTL.
	// Sanitizing the TTL and MaxTTL is not required now and can be performed
	// at credential issue time.
	if app.TokenTTL > app.TokenMaxTTL {
		return logical.ErrorResponse("token_ttl should not be greater than token_max_ttl"), nil
	}

	// Update only if value is supplied. Defaults to zero.
	if wrappedRaw, ok := data.GetOk("wrapped"); ok {
		app.Wrapped = time.Duration(wrappedRaw.(int)) * time.Second
	}

	// Store the entry.
	return nil, b.setAppEntry(req.Storage, appName, app)
}

func (b *backend) pathAppRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := b.appEntry(req.Storage, strings.ToLower(appName)); err != nil {
		return nil, err
	} else if app == nil {
		return nil, nil
	} else {
		// Convert the 'time.Duration' values to second.
		app.UserIDTTL = app.UserIDTTL / time.Second
		app.TokenTTL = app.TokenTTL / time.Second
		app.TokenMaxTTL = app.TokenMaxTTL / time.Second
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

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	if policiesRaw, ok := data.GetOk("policies"); ok {
		app.Policies = policyutil.ParsePolicies(policiesRaw.(string))
		return nil, b.setAppEntry(req.Storage, appName, app)
	} else {
		return logical.ErrorResponse("missing policies"), nil
	}
}

func (b *backend) pathAppPoliciesRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := b.appEntry(req.Storage, strings.ToLower(appName)); err != nil {
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

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	// Deleting a field means resetting the value in the entry.
	app.Policies = (&appStorageEntry{}).Policies

	return nil, b.setAppEntry(req.Storage, appName, app)
}

func (b *backend) pathAppNumUsesUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	if numUsesRaw, ok := data.GetOk("num_uses"); ok {
		app.NumUses = numUsesRaw.(int)
		if app.NumUses < 0 {
			return logical.ErrorResponse("num_uses cannot be negative"), nil
		}
		return nil, b.setAppEntry(req.Storage, appName, app)
	} else {
		return logical.ErrorResponse("missing num_uses"), nil
	}
}

func (b *backend) pathAppNumUsesRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := b.appEntry(req.Storage, strings.ToLower(appName)); err != nil {
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

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	// Deleting a field means resetting the value in the entry.
	app.NumUses = (&appStorageEntry{}).NumUses

	return nil, b.setAppEntry(req.Storage, appName, app)
}

func (b *backend) pathAppUserIDTTLUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	if userIDTTLRaw, ok := data.GetOk("userid_ttl"); ok {
		app.UserIDTTL = time.Second * time.Duration(userIDTTLRaw.(int))
		return nil, b.setAppEntry(req.Storage, appName, app)
	} else {
		return logical.ErrorResponse("missing userid_ttl"), nil
	}
}

func (b *backend) pathAppUserIDTTLRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := b.appEntry(req.Storage, strings.ToLower(appName)); err != nil {
		return nil, err
	} else if app == nil {
		return nil, nil
	} else {
		app.UserIDTTL = app.UserIDTTL / time.Second
		return &logical.Response{
			Data: map[string]interface{}{
				"userid_ttl": app.UserIDTTL,
			},
		}, nil
	}
}

func (b *backend) pathAppUserIDTTLDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	// Deleting a field means resetting the value in the entry.
	app.UserIDTTL = (&appStorageEntry{}).UserIDTTL

	return nil, b.setAppEntry(req.Storage, appName, app)
}

func (b *backend) pathAppTokenTTLUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	if tokenTTLRaw, ok := data.GetOk("token_ttl"); ok {
		if app.TokenTTL = time.Second * time.Duration(tokenTTLRaw.(int)); app.TokenTTL > app.TokenMaxTTL {
			return logical.ErrorResponse("token_ttl should not be greater than token_max_ttl"), nil
		}
		return nil, b.setAppEntry(req.Storage, appName, app)
	} else {
		return logical.ErrorResponse("missing token_ttl"), nil
	}
}

func (b *backend) pathAppTokenTTLRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := b.appEntry(req.Storage, strings.ToLower(appName)); err != nil {
		return nil, err
	} else if app == nil {
		return nil, nil
	} else {
		app.TokenTTL = app.TokenTTL / time.Second
		return &logical.Response{
			Data: map[string]interface{}{
				"token_ttl": app.TokenTTL,
			},
		}, nil
	}
}

func (b *backend) pathAppTokenTTLDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	// Deleting a field means resetting the value in the entry.
	app.TokenTTL = (&appStorageEntry{}).TokenTTL

	return nil, b.setAppEntry(req.Storage, appName, app)
}

func (b *backend) pathAppTokenMaxTTLUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	if tokenMaxTTLRaw, ok := data.GetOk("token_max_ttl"); ok {
		if app.TokenMaxTTL = time.Second * time.Duration(tokenMaxTTLRaw.(int)); app.TokenTTL > app.TokenMaxTTL {
			return logical.ErrorResponse("token_max_ttl should be greater than or equal to token_ttl"), nil
		}
		return nil, b.setAppEntry(req.Storage, appName, app)
	} else {
		return logical.ErrorResponse("missing token_max_ttl"), nil
	}
}

func (b *backend) pathAppTokenMaxTTLRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := b.appEntry(req.Storage, strings.ToLower(appName)); err != nil {
		return nil, err
	} else if app == nil {
		return nil, nil
	} else {
		app.TokenMaxTTL = app.TokenMaxTTL / time.Second
		return &logical.Response{
			Data: map[string]interface{}{
				"token_max_ttl": app.TokenMaxTTL,
			},
		}, nil
	}
}

func (b *backend) pathAppTokenMaxTTLDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	// Deleting a field means resetting the value in the entry.
	app.TokenMaxTTL = (&appStorageEntry{}).TokenMaxTTL

	return nil, b.setAppEntry(req.Storage, appName, app)
}

func (b *backend) pathAppWrappedUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	if wrappedRaw, ok := data.GetOk("wrapped"); ok {
		app.Wrapped = time.Duration(wrappedRaw.(int)) * time.Second
		return nil, b.setAppEntry(req.Storage, appName, app)
	} else {
		return logical.ErrorResponse("missing wrapped"), nil
	}
}

func (b *backend) pathAppWrappedRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := b.appEntry(req.Storage, strings.ToLower(appName)); err != nil {
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

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	app.Wrapped = (&appStorageEntry{}).Wrapped

	return nil, b.setAppEntry(req.Storage, appName, app)
}

func (b *backend) pathAppCredsRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	userID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UserID:%s", err)
	}
	data.Raw["user_id"] = userID
	return b.handleAppCredsCommon(req, data, false)
}

func (b *backend) pathAppCredsSpecificUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.handleAppCredsCommon(req, data, true)
}

func (b *backend) handleAppCredsCommon(req *logical.Request, data *framework.FieldData, specified bool) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	userID := data.Get("user_id").(string)
	if userID == "" {
		return logical.ErrorResponse("missing user_id"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return logical.ErrorResponse(fmt.Sprintf("app %s does not exist", appName)), nil
	}

	if err = b.registerUserIDEntry(req.Storage, selectorTypeApp, appName, userID, &userIDStorageEntry{
		NumUses: app.NumUses,
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

var appHelp = map[string][2]string{
	"app":                {"help", "desc"},
	"app-policies":       {"help", "desc"},
	"app-num-uses":       {"help", "desc"},
	"app-userid-ttl":     {"help", "desc"},
	"app-token-ttl":      {"help", "desc"},
	"app-token-max-ttl":  {"help", "desc"},
	"app-wrapped":        {"help", "desc"},
	"app-creds":          {"help", "desc"},
	"app-creds-specific": {"help", "desc"},
}
