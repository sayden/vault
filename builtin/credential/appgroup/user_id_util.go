package appgroup

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
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

type userIDStorageEntry struct {
	NumUses int           `json:"num_uses" structs:"num_uses" mapstructure:"num_uses"`
	TTL     time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	MaxTTL  time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
}

type validationResponse struct {
	SelectorType  string        `json:"selector_type" structs:"selector_type" mapstructure:"selector_type"`
	SelectorValue string        `json:"selector_value" structs:"selector_value" mapstructure:"selector_value"`
	TTL           time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	MaxTTL        time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
	Wrapped       time.Duration `json:"wrapped" structs:"wrapped" mapstructure:"wrapped"`
	Policies      []string      `json:"policies" structs:"policies" mapstructure:"policies"`
}

func (b *backend) validateUserID(s logical.Storage, selector, userID string) (*validationResponse, error) {
	if selector == "" {
		return nil, fmt.Errorf("missing selector")
	}
	if userID == "" {
		return nil, fmt.Errorf("missing userID")
	}

	selectorType := ""
	selectorValue := ""
	switch {
	case selector == "generic":
		selectorType = "generic"
		selectorValue = b.salt.SaltID(userID)
	case strings.HasPrefix(selector, "app/") || strings.HasPrefix(selector, "group/"):
		selectorFields := strings.SplitN(selector, "/", 2)
		if len(selectorFields) != 2 {
			return nil, fmt.Errorf("invalid length for selector in user ID")
		}
		selectorType = strings.TrimSpace(selectorFields[0])
		selectorValue = strings.TrimSpace(selectorFields[1])
		if selectorValue == "" {
			return nil, fmt.Errorf("missing selector value")
		}
	default:
		return nil, fmt.Errorf("unrecognized selector")
	}
	log.Printf("selectorType: %s", selectorType)
	log.Printf("selectorValue: %s", selectorValue)

	valid, err := b.userIDEntryValid(s, selectorType, selectorValue, userID)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, fmt.Errorf("invalid user ID")
	}

	return b.validateSelector(s, selectorType, selectorValue)
}

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
		resp.TTL = app.TTL
		resp.MaxTTL = app.MaxTTL
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
		resp.Policies = append(resp.Policies, groupPolicies...)
		resp.Policies = append(resp.Policies, group.AdditionalPolicies...)
		resp.TTL = group.TTL
		resp.MaxTTL = group.MaxTTL
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
			resp.Policies = append(resp.Policies, groupPolicies...)
			resp.Policies = append(resp.Policies, group.AdditionalPolicies...)
		}

		for _, appName := range generic.Apps {
			app, err := b.appEntry(s, appName)
			if err != nil {
				return nil, err
			}
			resp.Policies = append(resp.Policies, app.Policies...)
		}
		resp.Policies = append(resp.Policies, generic.AdditionalPolicies...)
		resp.TTL = generic.TTL
		resp.MaxTTL = generic.MaxTTL
		resp.Wrapped = generic.Wrapped
	default:
		return nil, fmt.Errorf("unknown selector type")
	}

	// Cap the ttl and max_ttl values.
	var err error
	resp.TTL, resp.MaxTTL, err = b.SanitizeTTL(resp.TTL, resp.MaxTTL)
	if err != nil {
		return nil, err
	}

	// Although wrapped is unrelated to the ttl and max_ttl values,
	// since it is issued out of the backend, it should respect the
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

	entryIndex := fmt.Sprintf("userid/%s/%s/%s", selectorType, selectorValue, b.salt.SaltID(strings.ToLower(userID)))
	if entry, err := logical.StorageEntryJSON(entryIndex, userIDEntry); err != nil {
		return err
	} else if err = s.Put(entry); err != nil {
		return err
	}

	b.userIDLocks[userID] = &sync.RWMutex{}
	return nil
}

// Takes in the plaintext value creates a HMAC of it and returns
// a role tag value containing both the plaintext part and the HMAC part.
func appendHMAC(value string, key string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("missing value")
	}

	if key == "" {
		return "", fmt.Errorf("missing key")
	}

	// Create the HMAC of the value
	hmacB64, err := createHMACBase64(key, value)
	if err != nil {
		return "", err
	}

	// attach the HMAC to the value
	return fmt.Sprintf("%s:%s", value, hmacB64), nil
}

// Creates base64 encoded HMAC using a supplied key.
func createHMACBase64(key, value string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("invalid HMAC key")
	}
	hm := hmac.New(sha256.New, []byte(key))
	hm.Write([]byte(value))

	// base64 encode the hmac bytes.
	return base64.StdEncoding.EncodeToString(hm.Sum(nil)), nil
}

// Iterates through all the apps and fetches the policies of each.
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
