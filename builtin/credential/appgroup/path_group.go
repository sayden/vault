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

// groupStorageEntry stores all the options that are set on a Group
type groupStorageEntry struct {
	// All the participating Apps of the Group
	Apps []string `json:"apps" structs:"apps" mapstructure:"apps"`

	// Number of times the UserID generated against the Group can be used to perform login
	NumUses int `json:"num_uses" structs:"num_uses" mapstructure:"num_uses"`

	// Duration (less than the backend mount's max TTL) after which a UserID generated against the Group will expire
	UserIDTTL time.Duration `json:"userid_ttl" structs:"userid_ttl" mapstructure:"userid_ttl"`

	// Duration before which an issued token must be renewed
	TokenTTL time.Duration `json:"token_ttl" structs:"token_ttl" mapstructure:"token_ttl"`

	// Duration after which an issued token should not be allowed to be renewed
	TokenMaxTTL time.Duration `json:"token_max_ttl" structs:"token_max_ttl" mapstructure:"token_max_ttl"`

	// Along with the combined set of Apps' policies, the policies in this list will be
	// added to capabilities of the token issued, when a UserID generated against a Group
	// is used perform the login.
	AdditionalPolicies []string `json:"additional_policies" structs:"additional_policies" mapstructure:"additional_policies"`
}

// groupPaths creates all the paths that are used to register and manage an Group.
//
// Paths returned:
// group/
// group/<group_name>
// group/policies
// group/num-uses
// group/userid-ttl
// group/token-ttl
// group/token-max-ttl
// group/<group_name>/creds
// group/<group_name>/creds-specific
func groupPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "group/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathGroupList,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-list"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-list"][1]),
		},
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

// pathGroupList is used to list all the Groups registered with the backend.
func (b *backend) pathGroupList(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.groupLock.RLock()
	defer b.groupLock.RUnlock()

	groups, err := req.Storage.List("group/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(groups), nil
}

// setAppEntry grabs a write lock and stores the options on a Group into the storage
func (b *backend) setGroupEntry(s logical.Storage, groupName string, group *groupStorageEntry) error {
	b.groupLock.Lock()
	defer b.groupLock.Unlock()

	if entry, err := logical.StorageEntryJSON("group/"+strings.ToLower(groupName), group); err != nil {
		return err
	} else {
		return s.Put(entry)
	}
}

// groupEntry grabs the read lock and fetches the options of an Group from the storage
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

// pathAppCreateUpdate registers a new Group with the backend or updates the options
// of an existing Group
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

	if group.TokenMaxTTL > time.Duration(0) && group.TokenTTL > group.TokenMaxTTL {
		return logical.ErrorResponse("token_ttl should not be greater than token_max_ttl"), nil
	}

	// Store the entry.
	return nil, b.setGroupEntry(req.Storage, groupName, group)
}

// pathGroupRead grabs a read lock and reads the options set on the Group from the storage
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

		return &logical.Response{
			Data: structs.New(group).Map(),
		}, nil
	}
}

// pathGroupDelete removes the Group from the storage
func (b *backend) pathGroupDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}
	b.groupLock.Lock()
	defer b.groupLock.Unlock()

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
		group.TokenTTL = time.Second * time.Duration(tokenTTLRaw.(int))
		if group.TokenMaxTTL > time.Duration(0) && group.TokenTTL > group.TokenMaxTTL {
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
		group.TokenMaxTTL = time.Second * time.Duration(tokenMaxTTLRaw.(int))
		if group.TokenMaxTTL > time.Duration(0) && group.TokenTTL > group.TokenMaxTTL {
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
		NumUses:   group.NumUses,
		UserIDTTL: group.UserIDTTL,
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
	"group-list": {
		"Lists all the Groups registered with the backend.",
		"The list will contain the names of the Groups.",
	},
	"group": {
		"Create a group of Apps and define custom options on it.",
		`A group registered with the backend represents a group of Apps. The options
set on the group supercedes the options set on the participating Apps.
Ther no single set of policies that are to be applied on the group.
The policies are dynamically determined during the login period. The
effective polices on the group is a union of all the policies of all
the participating Apps. However, a comma-delimited set of 'additional_policies'
can be supplied on the group. These policies will be appended to the
effective policies.`,
	},
	"group-apps": {
		"Comma-delimited list of participating Apps of the group.",
		`All the Apps listed here should be registered with the backend before the
login operation is performed. `,
	},
	"group-additional-policies": {
		`Additional policies to be assigned to the tokens issued by using the UserIDs
that were generated against this group.`,
		`If a UserID is generated/assigned against this group, and if these UserIDs
are used to perform a login operation, the tokens issued will have a
combined set of policies from each participating App. In addition,
the 'additional_policies' defined using this option will be appended
to the issued token's effective policies.`,
	},
	"group-num-uses": {
		"Use limit of the UserID generated against the group.",
		`If the UserIDs are generated/assigned against the group using
'group/<group_name>/creds' or 'group/<group_name>/creds-specific'
endpoints, then the number of times that these UserIDs can access
the participating Apps is defined by this option.`,
	},
	"group-userid-ttl": {
		`Duration in seconds, representing the lifetime of the UserIDs
that are generated against the Group using 'group/<group_name>/creds'
or 'group/<group_name>/creds-specific' endpoints.`,
		`If the UserIDs are generated against the Group using 'group/<group_name>/creds'
or 'group/<group_name>/creds-specific' endpoints, then those UserIDs
will expire after the duration specified by this option. Note that this
value will be capped by the backend mount's maximux TTL value.`,
	},
	`group-token-ttl`: {
		`Duration in seconds, the lifetime of the token issued by using
the UserID that is generated against this Group, before which the token
needs to be renewed.`,
		`If UserIDs are generated against the Group, using 'group/<group_name>/creds'
or the 'group/<group_name>/creds-specific' endpoints, and if those UserIDs
are used to perform the login operation, then the value of 'token-ttl'
defines the lifetime of the token issued, before which teh token needs
to be renewed.`,
	},
	"group-token-max-ttl": {
		`Duration in seconds, the maximux lifetime of the tokens issued by using the UserID that were generated against the Group, after which the tokens are not allowed to be renewed.`,
		`If UserIDs are generated against the Group using 'group/<group_name>/creds'
or the 'group/<group_name>/creds-specific' endpoints, and if those UserIDs
are used to perform the login operation, then the value of 'token-max-ttl'
defines the maximum lifetime of the tokens issued, after which the tokens
cannot be renewed. A reauthentication is required after this duration.
This value will be capped by the backend mount's maximux TTL value.`,
	},
	"group-creds": {
		"Generate a UserID against this Group.",
		`The UserID generated using this endpoint will be scoped to access
the participant Apps of this Group. The properties of this UserID will
be based on the options set on the Group. It will expire after a period
defined by the 'userid_ttl' option on the Group and/or the backend mount's
maximum TTL value.`,
	},
	"group-creds-specific": {
		"Assign a UserID of choice against the Group.",
		`This option is not recommended unless there is a specific need
to do so. This will assign a client supplied UserID to be used to access
the participating Apps of the Group. This UserID will behavie similarly
to the UserIDs generated by the backend. The properties of this UserID
will be based on the options set on the Group. It will expire after a
period defined by the 'userid_ttl' option on the Group and/or the backend
mount's maximux TTL value.`,
	},
}
