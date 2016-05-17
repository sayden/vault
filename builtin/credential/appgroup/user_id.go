package appgroup

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
)

const (
	selectorTypeApp     = "app"
	selectorTypeGroup   = "group"
	selectorTypeGeneric = "generic"
)

// userIDStorageEntry represents the information stored in storage when a UserID is created.
// The structure of the UserID storage entry is the same for all the types of UserIDs generated.
type userIDStorageEntry struct {
	// Number of times this UserID can be used to perform the login operation
	NumUses int `json:"num_uses" structs:"num_uses" mapstructure:"num_uses"`

	// Duration after which this UserID should expire. This is capped by the backend mount's
	// max TTL value.
	UserIDTTL time.Duration `json:"userid_ttl" structs:"userid_ttl" mapstructure:"userid_ttl"`

	// The time in UTC when the UserID was created
	CreationTime time.Time `json:"creation_time" structs:"creation_time" mapstructure:"creation_time"`

	// The time in UTC when the UserID becomes eligible for tidy operation.
	// Tidying is performed by the PeriodicFunc of the backend which is 1 minute apart.
	ExpirationTime time.Time `json:"expiration_time" structs:"expiration_time" mapstructure:"expiration_time"`

	// The time in UTC representing the last time this storage entry was modified
	LastUpdatedTime time.Time `json:"last_updated_time" structs:"last_updated_time" mapstructure:"last_updated_time"`
}

// validationResponse will be the result of credentials verification performed during login.
// This contains information that either needs to be returned to the client or information
// required to be stored as metadata in the response, and/or the information required to
// create the client token.
type validationResponse struct {
	SelectorType  string        `json:"selector_type" structs:"selector_type" mapstructure:"selector_type"`
	SelectorValue string        `json:"selector_value" structs:"selector_value" mapstructure:"selector_value"`
	TokenTTL      time.Duration `json:"token_ttl" structs:"token_ttl" mapstructure:"token_ttl"`
	TokenMaxTTL   time.Duration `json:"token_max_ttl" structs:"token_max_ttl" mapstructure:"token_max_ttl"`
	Wrapped       time.Duration `json:"wrapped" structs:"wrapped" mapstructure:"wrapped"`
	Policies      []string      `json:"policies" structs:"policies" mapstructure:"policies"`
}

// Identifies the supplied selector and validates it, checks if the supplied user ID
// has a corresponding entry in the backend and udpates the use count if needed.
func (b *backend) validateCredentials(s logical.Storage, selector, userID string) (*validationResponse, error) {
	if selector == "" {
		return nil, fmt.Errorf("missing selector")
	}
	if userID == "" {
		return nil, fmt.Errorf("missing userID")
	}

	// From the selector field supplied as the credential, detect the type of UserID
	// supplied. UserID will be verified based on the type.
	selectorType := ""
	selectorValue := ""
	switch {
	case selector == "generic":
		selectorType = "generic"
		selectorValue = b.salt.SaltID(userID)
	case strings.HasPrefix(selector, "app/") || strings.HasPrefix(selector, "group/"):
		selectorFields := strings.SplitN(selector, "/", 2)
		if len(selectorFields) != 2 {
			return nil, fmt.Errorf("invalid selector; selector type and value could not be parsed")
		}
		selectorType = strings.TrimSpace(selectorFields[0])
		selectorValue = strings.TrimSpace(selectorFields[1])
		if selectorValue == "" {
			return nil, fmt.Errorf("missing selector value")
		}
	default:
		return nil, fmt.Errorf("unrecognized selector")
	}

	// Do the selector validation first. If this results in an error, the UserID
	// entry should not be modified. Return the validation response if the UserID
	// is found to be valid and if the UserID entry is updated properly.
	validationResp, err := b.validateSelector(s, selectorType, selectorValue)
	if err != nil {
		return nil, err
	}

	// Check if the user ID supplied is valid. If use limit was specified
	// on the user ID, it will be decremented in this call.
	valid, err := b.userIDEntryValid(s, selectorType, selectorValue, userID)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, fmt.Errorf("invalid user ID")
	}

	return validationResp, nil
}

// Check if there exists an entry in the name of selectorValue for the selectorType supplied.
// Prepares a response containing the combined set of policies, TTL and Wrapped values that are
// applicable to the login.
func (b *backend) validateSelector(s logical.Storage, selectorType, selectorValue string) (*validationResponse, error) {
	resp := &validationResponse{
		SelectorType:  selectorType,
		SelectorValue: selectorValue,
	}
	switch selectorType {
	case selectorTypeApp:
		app, err := b.appEntry(s, selectorValue)
		if err != nil {
			return nil, err
		}
		if app == nil {
			return nil, fmt.Errorf("app referred by the user ID does not exist")
		}
		resp.Policies = app.Policies
		resp.TokenTTL = app.TokenTTL
		resp.TokenMaxTTL = app.TokenMaxTTL
		resp.Wrapped = app.Wrapped
	case selectorTypeGroup:
		group, err := b.groupEntry(s, selectorValue)
		if err != nil {
			return nil, err
		}
		if group == nil {
			return nil, fmt.Errorf("group referred by the user ID does not exist")
		}
		groupPolicies, err := b.fetchPolicies(s, group.Apps)
		if err != nil {
			return nil, err
		}
		// Append the union of all the policies from all the apps on the group
		resp.Policies = append(resp.Policies, groupPolicies...)

		// Append the additional policies set on the group
		resp.Policies = append(resp.Policies, group.AdditionalPolicies...)

		resp.TokenTTL = group.TokenTTL
		resp.TokenMaxTTL = group.TokenMaxTTL
		resp.Wrapped = group.Wrapped
	case selectorTypeGeneric:
		generic, err := b.genericEntry(s, selectorValue)
		if err != nil {
			return nil, err
		}
		if generic == nil {
			return nil, fmt.Errorf("generic credential referred by the user ID does not exist")
		}
		for _, groupName := range generic.Groups {
			group, err := b.groupEntry(s, groupName)
			if err != nil {
				return nil, err
			}
			groupPolicies, err := b.fetchPolicies(s, group.Apps)
			if err != nil {
				return nil, err
			}
			// Append the union of all the policies from all the apps on the group
			resp.Policies = append(resp.Policies, groupPolicies...)
			// Append the additional policies set on the group
			resp.Policies = append(resp.Policies, group.AdditionalPolicies...)
		}

		for _, appName := range generic.Apps {
			app, err := b.appEntry(s, appName)
			if err != nil {
				return nil, err
			}
			// Append the policies set on the app
			resp.Policies = append(resp.Policies, app.Policies...)
		}

		// Append the additonal policies set on the generic entry
		resp.Policies = append(resp.Policies, generic.AdditionalPolicies...)

		resp.TokenTTL = generic.TokenTTL
		resp.TokenMaxTTL = generic.TokenMaxTTL
		resp.Wrapped = generic.Wrapped
	default:
		return nil, fmt.Errorf("unknown selector type")
	}

	// Cap the token_ttl and token_max_ttl values.
	var err error
	resp.TokenTTL, resp.TokenMaxTTL, err = b.SanitizeTTL(resp.TokenTTL, resp.TokenMaxTTL)
	if err != nil {
		return nil, err
	}

	// Even though wrapped is unrelated to the token_ttl and token_max_ttl
	// values, since it is issued out of the backend, it should respect the
	// backend's boundaries.
	if resp.Wrapped > b.System().MaxLeaseTTL() {
		resp.Wrapped = b.System().MaxLeaseTTL()
	}

	return resp, nil
}

func (b *backend) userIDEntryValid(s logical.Storage, selectorType, selectorValue, userID string) (bool, error) {
	lock := b.userIDLocks[userID]
	if lock == nil {
		return false, nil
	}

	entryIndex := fmt.Sprintf("userid/%s/%s/%s", selectorType, selectorValue, b.salt.SaltID(strings.ToLower(userID)))

	lock.RLock()

	result := userIDStorageEntry{}
	if entry, err := s.Get(entryIndex); err != nil {
		lock.RUnlock()
		return false, err
	} else if entry == nil {
		lock.RUnlock()
		return false, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		lock.RUnlock()
		return false, err
	}

	if result.NumUses == 0 {
		lock.RUnlock()
		return true, nil
	}

	lock.RUnlock()
	lock.Lock()
	defer lock.Unlock()

	// Lock switching might have changed the data. Refresh the contents.
	result = userIDStorageEntry{}
	if entry, err := s.Get(entryIndex); err != nil {
		return false, err
	} else if entry == nil {
		return false, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		return false, err
	}

	if result.NumUses == 1 {
		if err := s.Delete(entryIndex); err != nil {
			return false, err
		}
		if selectorType == selectorTypeGeneric {
			if err := b.deleteGenericEntry(s, selectorValue); err != nil {
				return false, err
			}
		}
		b.userIDLocks[userID] = nil
	} else {
		result.NumUses -= 1
		result.LastUpdatedTime = time.Now().UTC()
		if entry, err := logical.StorageEntryJSON(entryIndex, &result); err != nil {
			return false, fmt.Errorf("failed to decrement the num_uses for user ID:%s", userID)
		} else if err = s.Put(entry); err != nil {
			return false, fmt.Errorf("failed to decrement the num_uses for user ID:%s", userID)
		}
	}
	return true, nil
}

func (b *backend) registerUserIDEntry(s logical.Storage, selectorType, selectorValue, userID string, userIDEntry *userIDStorageEntry) error {
	if b.userIDLocks[userID] != nil {
		return fmt.Errorf("user ID is already registered")
	}

	currentTime := time.Now().UTC()
	userIDEntry.CreationTime = currentTime
	userIDEntry.LastUpdatedTime = currentTime

	// If UserIDTTL is not specified or if it crosses the backend mount's limit, cap the expiration to
	// backend's max. Otherwise, use it to determine the expiration time.
	if userIDEntry.UserIDTTL <= time.Duration(0) || userIDEntry.UserIDTTL > b.System().MaxLeaseTTL() {
		userIDEntry.ExpirationTime = currentTime.Add(b.System().MaxLeaseTTL())
	} else {
		userIDEntry.ExpirationTime = currentTime.Add(userIDEntry.UserIDTTL)
	}

	entryIndex := fmt.Sprintf("userid/%s/%s/%s", selectorType, selectorValue, b.salt.SaltID(strings.ToLower(userID)))
	if entry, err := logical.StorageEntryJSON(entryIndex, userIDEntry); err != nil {
		return err
	} else if err = s.Put(entry); err != nil {
		return err
	}

	b.userIDLocks[userID] = &sync.RWMutex{}
	return nil
}

// Iterates through all the Apps and fetches the policies of each.
// An error is thrown if any App in the list does not exist.
func (b *backend) fetchPolicies(s logical.Storage, apps []string) ([]string, error) {
	var policies []string
	for _, appName := range apps {
		app, err := b.appEntry(s, appName)
		if err != nil {
			return nil, err
		}
		if app == nil {
			return nil, fmt.Errorf("app %s does not exist", appName)
		}
		policies = append(policies, app.Policies...)
	}
	return strutil.RemoveDuplicates(policies), nil
}
