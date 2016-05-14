package appgroup

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/structs"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type groupStorageEntry struct {
	Apps               []string      `json:"apps" structs:"apps" mapstructure:"apps"`
	NumUses            int           `json:"num_uses" structs:"num_uses" mapstructure:"num_uses"`
	UserIDTTL          time.Duration `json:"userid_ttl" structs:"userid_ttl" mapstructure:"userid_ttl"`
	TokenTTL           time.Duration `json:"token_ttl" structs:"token_ttl" mapstructure:"token_ttl"`
	TokenMaxTTL        time.Duration `json:"token_max_ttl" structs:"token_max_ttl" mapstructure:"token_max_ttl"`
	Wrapped            time.Duration `json:"wrapped" structs:"wrapped" mapstructure:"wrapped"`
	AdditionalPolicies []string      `json:"additional_policies" structs:"additional_policies" mapstructure:"additional_policies"`
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
				"apps": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "",
					Description: "Comma separated list of Apps belonging to the group",
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
					Description: `Duration in seconds, if specified, enables the Cubbyhole mode. In this mode,
the UserID creation endpoints will not return the UserID directly. Instead,
a new token will be returned with the UserID stored in its Cubbyhole. The
value of 'wrapped' is the duration after which the returned token expires.
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
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/apps$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
				"apps": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "",
					Description: "Comma separated list of Apps belonging to the group",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathGroupAppsUpdate,
				logical.ReadOperation:   b.pathGroupAppsRead,
				logical.DeleteOperation: b.pathGroupAppsDelete,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-apps"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-apps"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/additional-policies$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
				"additional_policies": &framework.FieldSchema{
					Type:    framework.TypeString,
					Default: "",
					Description: `Comma separated list of policies for the Group. The UserID created against the Group,
will have access to the union of all the policies of the Apps. In
addition to those, a set of policies can be assigned using this.
`,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathGroupAdditionalPoliciesUpdate,
				logical.ReadOperation:   b.pathGroupAdditionalPoliciesRead,
				logical.DeleteOperation: b.pathGroupAdditionalPoliciesDelete,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-additional-policies"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-additional-policies"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/num-uses$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
				"num_uses": &framework.FieldSchema{
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
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/userid-ttl$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
				"userid_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued UserID should expire.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathGroupUserIDTTLUpdate,
				logical.ReadOperation:   b.pathGroupUserIDTTLRead,
				logical.DeleteOperation: b.pathGroupUserIDTTLDelete,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-userid-ttl"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-userid-ttl"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/token-ttl$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
				"token_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued token should expire.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathGroupTokenTTLUpdate,
				logical.ReadOperation:   b.pathGroupTokenTTLRead,
				logical.DeleteOperation: b.pathGroupTokenTTLDelete,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-token-ttl"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-token-ttl"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/token-max-ttl$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
				"token_max_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued token should not be allowed to be renewed.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathGroupTokenMaxTTLUpdate,
				logical.ReadOperation:   b.pathGroupTokenMaxTTLRead,
				logical.DeleteOperation: b.pathGroupTokenMaxTTLDelete,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-token-max-ttl"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-token-max-ttl"][1]),
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
				"user_id": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "",
					Description: "NOT USER SUPPLIED. UNDOCUMENTED.",
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
					Default:     "",
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

func (b *backend) setGroupEntry(s logical.Storage, groupName string, group *groupStorageEntry) error {
	b.groupLock.Lock()
	defer b.groupLock.Unlock()

	if entry, err := logical.StorageEntryJSON("group/"+strings.ToLower(groupName), group); err != nil {
		return err
	} else {
		return s.Put(entry)
	}
}

func (b *backend) groupEntry(s logical.Storage, groupName string) (*groupStorageEntry, error) {
	if groupName == "" {
		return nil, fmt.Errorf("missing group_name")
	}

	var result groupStorageEntry

	b.groupLock.RLock()
	defer b.groupLock.RUnlock()

	if entry, err := s.Get("group/" + strings.ToLower(groupName)); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) pathGroupCreateUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, groupName)
	if err != nil {
		return nil, err
	}
	if group == nil {
		group = &groupStorageEntry{}
	}

	if appsRaw, ok := data.GetOk("apps"); ok {
		group.Apps = strutil.RemoveDuplicates(strings.Split(appsRaw.(string), ","))
	} else if req.Operation == logical.CreateOperation {
		group.Apps = strutil.RemoveDuplicates(strings.Split(data.Get("apps").(string), ","))
	}

	if additionalPoliciesRaw, ok := data.GetOk("additional_policies"); ok {
		group.AdditionalPolicies = policyutil.ParsePolicies(additionalPoliciesRaw.(string))
	} else if req.Operation == logical.CreateOperation {
		group.AdditionalPolicies = policyutil.ParsePolicies(data.Get("additional_policies").(string))
	}

	if numUsesRaw, ok := data.GetOk("num_uses"); ok {
		group.NumUses = numUsesRaw.(int)
	} else if req.Operation == logical.CreateOperation {
		group.NumUses = data.Get("num_uses").(int)
	}

	if group.NumUses < 0 {
		return logical.ErrorResponse("num_uses cannot be negative"), nil
	}

	if userIDTTLRaw, ok := data.GetOk("userid_ttl"); ok {
		group.UserIDTTL = time.Second * time.Duration(userIDTTLRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		group.UserIDTTL = time.Second * time.Duration(data.Get("userid_ttl").(int))
	}

	if tokenTTLRaw, ok := data.GetOk("token_ttl"); ok {
		group.TokenTTL = time.Second * time.Duration(tokenTTLRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		group.TokenTTL = time.Second * time.Duration(data.Get("token_ttl").(int))
	}

	if tokenMaxTTLRaw, ok := data.GetOk("token_max_ttl"); ok {
		group.TokenMaxTTL = time.Second * time.Duration(tokenMaxTTLRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		group.TokenMaxTTL = time.Second * time.Duration(data.Get("token_max_ttl").(int))
	}

	if group.TokenTTL > group.TokenMaxTTL {
		return logical.ErrorResponse("token_ttl should not be greater than token_max_ttl"), nil
	}

	if wrappedRaw, ok := data.GetOk("wrapped"); ok {
		group.Wrapped = time.Second * time.Duration(wrappedRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		group.Wrapped = time.Second * time.Duration(data.Get("wrapped").(int))
	}

	// Store the entry.
	return nil, b.setGroupEntry(req.Storage, groupName, group)
}

func (b *backend) pathGroupRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	if group, err := b.groupEntry(req.Storage, strings.ToLower(groupName)); err != nil {
		return nil, err
	} else if group == nil {
		return nil, nil
	} else {
		// Convert the values to second
		group.UserIDTTL = group.UserIDTTL / time.Second
		group.TokenTTL = group.TokenTTL / time.Second
		group.TokenMaxTTL = group.TokenMaxTTL / time.Second
		group.Wrapped = group.Wrapped / time.Second

		return &logical.Response{
			Data: structs.New(group).Map(),
		}, nil
	}
}

func (b *backend) pathGroupDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	return nil, req.Storage.Delete("group/" + strings.ToLower(groupName))
}

func (b *backend) pathGroupAppsUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	if appsRaw, ok := data.GetOk("apps"); ok {
		group.Apps = strings.Split(appsRaw.(string), ",")
		return nil, b.setGroupEntry(req.Storage, groupName, group)
	} else {
		return logical.ErrorResponse("missing apps"), nil
	}
}

func (b *backend) pathGroupAppsRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	if group, err := b.groupEntry(req.Storage, strings.ToLower(groupName)); err != nil {
		return nil, err
	} else if group == nil {
		return nil, nil
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"apps": group.Apps,
			},
		}, nil
	}
}

func (b *backend) pathGroupAppsDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	group.Apps = (&groupStorageEntry{}).Apps

	return nil, b.setGroupEntry(req.Storage, groupName, group)
}

func (b *backend) pathGroupAdditionalPoliciesUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	if additionalPoliciesRaw, ok := data.GetOk("additional_policies"); ok {
		group.AdditionalPolicies = policyutil.ParsePolicies(additionalPoliciesRaw.(string))
		return nil, b.setGroupEntry(req.Storage, groupName, group)
	} else {
		return logical.ErrorResponse("missing additional_policies"), nil
	}
}

func (b *backend) pathGroupAdditionalPoliciesRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	if group, err := b.groupEntry(req.Storage, strings.ToLower(groupName)); err != nil {
		return nil, err
	} else if group == nil {
		return nil, nil
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"additional_policies": group.AdditionalPolicies,
			},
		}, nil
	}
}

func (b *backend) pathGroupAdditionalPoliciesDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	group.AdditionalPolicies = (&groupStorageEntry{}).AdditionalPolicies

	return nil, b.setGroupEntry(req.Storage, groupName, group)
}

func (b *backend) pathGroupNumUsesUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	if numUsesRaw, ok := data.GetOk("num_uses"); ok {
		group.NumUses = numUsesRaw.(int)
		if group.NumUses < 0 {
			return logical.ErrorResponse("num_uses cannot be negative"), nil
		}
		return nil, b.setGroupEntry(req.Storage, groupName, group)
	} else {
		return logical.ErrorResponse("missing num_uses"), nil
	}
}

func (b *backend) pathGroupNumUsesRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	if group, err := b.groupEntry(req.Storage, strings.ToLower(groupName)); err != nil {
		return nil, err
	} else if group == nil {
		return nil, nil
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"num_uses": group.NumUses,
			},
		}, nil
	}
}

func (b *backend) pathGroupNumUsesDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	group.NumUses = (&groupStorageEntry{}).NumUses

	return nil, b.setGroupEntry(req.Storage, groupName, group)
}

func (b *backend) pathGroupUserIDTTLUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	if userIDTTLRaw, ok := data.GetOk("userid_ttl"); ok {
		group.UserIDTTL = time.Second * time.Duration(userIDTTLRaw.(int))
		return nil, b.setGroupEntry(req.Storage, groupName, group)
	} else {
		return logical.ErrorResponse("missing userid_ttl"), nil
	}
}

func (b *backend) pathGroupUserIDTTLRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	if group, err := b.groupEntry(req.Storage, strings.ToLower(groupName)); err != nil {
		return nil, err
	} else if group == nil {
		return nil, nil
	} else {
		group.UserIDTTL = group.UserIDTTL / time.Second
		return &logical.Response{
			Data: map[string]interface{}{
				"userid_ttl": group.UserIDTTL,
			},
		}, nil
	}
}

func (b *backend) pathGroupUserIDTTLDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	group.UserIDTTL = (&groupStorageEntry{}).UserIDTTL

	return nil, b.setGroupEntry(req.Storage, groupName, group)
}

func (b *backend) pathGroupTokenTTLUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	if tokenTTLRaw, ok := data.GetOk("token_ttl"); ok {
		if group.TokenTTL = time.Second * time.Duration(tokenTTLRaw.(int)); group.TokenTTL > group.TokenMaxTTL {
			return logical.ErrorResponse("token_ttl should not be greater than token_max_ttl"), nil
		}
		return nil, b.setGroupEntry(req.Storage, groupName, group)
	} else {
		return logical.ErrorResponse("missing token_ttl"), nil
	}
}

func (b *backend) pathGroupTokenTTLRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	if group, err := b.groupEntry(req.Storage, strings.ToLower(groupName)); err != nil {
		return nil, err
	} else if group == nil {
		return nil, nil
	} else {
		group.TokenTTL = group.TokenTTL / time.Second
		return &logical.Response{
			Data: map[string]interface{}{
				"token_ttl": group.TokenTTL,
			},
		}, nil
	}
}

func (b *backend) pathGroupTokenTTLDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	group.TokenTTL = (&groupStorageEntry{}).TokenTTL

	return nil, b.setGroupEntry(req.Storage, groupName, group)
}

func (b *backend) pathGroupTokenMaxTTLUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	if tokenMaxTTLRaw, ok := data.GetOk("token_max_ttl"); ok {
		if group.TokenMaxTTL = time.Second * time.Duration(tokenMaxTTLRaw.(int)); group.TokenTTL > group.TokenMaxTTL {
			return logical.ErrorResponse("token_max_ttl should be greater than token_ttl"), nil
		}
		return nil, b.setGroupEntry(req.Storage, groupName, group)
	} else {
		return logical.ErrorResponse("missing token_max_ttl"), nil
	}
}

func (b *backend) pathGroupTokenMaxTTLRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	if group, err := b.groupEntry(req.Storage, strings.ToLower(groupName)); err != nil {
		return nil, err
	} else if group == nil {
		return nil, nil
	} else {
		group.TokenMaxTTL = group.TokenMaxTTL / time.Second
		return &logical.Response{
			Data: map[string]interface{}{
				"token_max_ttl": group.TokenMaxTTL,
			},
		}, nil
	}
}

func (b *backend) pathGroupTokenMaxTTLDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	group.TokenMaxTTL = (&groupStorageEntry{}).TokenMaxTTL

	return nil, b.setGroupEntry(req.Storage, groupName, group)
}

func (b *backend) pathGroupWrappedUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	if wrappedRaw, ok := data.GetOk("wrapped"); ok {
		group.Wrapped = time.Second * time.Duration(wrappedRaw.(int))
		return nil, b.setGroupEntry(req.Storage, groupName, group)
	} else {
		return logical.ErrorResponse("missing wrapped"), nil
	}
}

func (b *backend) pathGroupWrappedRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	if group, err := b.groupEntry(req.Storage, strings.ToLower(groupName)); err != nil {
		return nil, err
	} else if group == nil {
		return nil, nil
	} else {
		group.Wrapped = group.Wrapped / time.Second
		return &logical.Response{
			Data: map[string]interface{}{
				"wrapped": group.Wrapped,
			},
		}, nil
	}
}

func (b *backend) pathGroupWrappedDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	group.Wrapped = (&groupStorageEntry{}).Wrapped

	return nil, b.setGroupEntry(req.Storage, groupName, group)
}

func (b *backend) pathGroupCredsRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	userID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UserID:%s", err)
	}
	data.Raw["user_id"] = userID
	return b.handleGroupCredsCommon(req, data, false)
}

func (b *backend) pathGroupCredsSpecificUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.handleGroupCredsCommon(req, data, true)
}

func (b *backend) handleGroupCredsCommon(req *logical.Request, data *framework.FieldData, specific bool) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	userID := data.Get("user_id").(string)
	if userID == "" {
		return logical.ErrorResponse("missing user_id"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return logical.ErrorResponse(fmt.Sprintf("Group %s does not exist", groupName)), nil
	}

	if err = b.registerUserIDEntry(req.Storage, selectorTypeGroup, groupName, userID, &userIDStorageEntry{
		NumUses: group.NumUses,
	}); err != nil {
		return nil, fmt.Errorf("failed to store user ID: %s", err)
	}

	if specific {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"user_id": userID,
		},
	}, nil
}

var groupHelp = map[string][2]string{
	"group":                     {"help", "desc"},
	"group-apps":                {"help", "desc"},
	"group-additional-policies": {"help", "desc"},
	"group-num-uses":            {"help", "desc"},
	"group-userid-ttl":          {"help", "desc"},
	"group-token-ttl":           {"help", "desc"},
	"group-token-max-ttl":       {"help", "desc"},
	"group-wrgrouped":           {"help", "desc"},
	"group-creds":               {"help", "desc"},
	"group-creds-specific":      {"help", "desc"},
}
