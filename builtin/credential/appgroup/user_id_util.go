package appgroup

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
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

type userIDStorageEntry struct {
	NumUses int           `json:"num_uses" structs:"num_uses" mapstructure:"num_uses"`
	TTL     time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	MaxTTL  time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
}

type parseUserIDResponse struct {
	Verified      bool   `json:"verified" structs:"verified" mapstructure:"verified"`
	SelectorType  string `json:"selector_type" structs:"selector_type" mapstructure:"selector_type"`
	SelectorValue string `json:"selector_value" structs:"selector_value" mapstructure:"selector_value"`
}

type validateSelectorResponse struct {
	SelectorType  string        `json:"selector_type" structs:"selector_type" mapstructure:"selector_type"`
	SelectorValue string        `json:"selector_value" structs:"selector_value" mapstructure:"selector_value"`
	TTL           time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	MaxTTL        time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
	Wrapped       time.Duration `json:"wrapped" structs:"wrapped" mapstructure:"wrapped"`
	Policies      []string      `json:"policies" structs:"policies" mapstructure:"policies"`
}

func (b *backend) validateUserID(s logical.Storage, userID string) (*validateSelectorResponse, error) {
	// First ensure that the UserID presented is not tampered with.
	// After authentication, get the selector type and value.
	parseResp, err := b.parseAndVerifyUserID(s, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse and verify user ID: %s", err)
	}

	// Fail if HMAC verification was unsuccessful or if the selector
	// type and value was not present in the UserID.
	if parseResp == nil ||
		!parseResp.Verified ||
		parseResp.SelectorType == "" ||
		parseResp.SelectorValue == "" {
		return nil, fmt.Errorf("failed to parse and verify user ID")
	}

	// Now, it is verified that the UserID is not modified. But it
	// may have been deleted.
	//
	// See if there is a corresponding entry for the presented UserID.
	// The storage index for UserIDs will be created by salting the
	// 'prepared' UserID value. Meaning, salting will be done on the
	// UserID after HMAC is attached to it. So, a direct lookup of the
	// presented UserID (and not the plaintext part of it), based on
	// the selector, should return the entry.
	valid, err := b.userIDEntryValid(s, parseResp.SelectorType, parseResp.SelectorValue, userID)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, fmt.Errorf("invalid user ID")
	}

	// Return the effective configuration values based on the current snapshot of the configuration.
	return b.validateSelector(s, parseResp.SelectorType, parseResp.SelectorValue)
}

func (b *backend) validateSelector(s logical.Storage, selectorType, selectorValue string) (*validateSelectorResponse, error) {
	resp := &validateSelectorResponse{
		SelectorType:  selectorType,
		SelectorValue: selectorValue,
	}
	// Based on the selector type, prepare the "effective" policies.
	// This is credential issue time, so validate the TTL and MaxTTL
	// boundaries too.
	//var policies []string
	//var ttl time.Duration
	//var maxTTL time.Duration
	//var wrapped time.Duration
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

func (b *backend) parseAndVerifyUserID(s logical.Storage, userID string) (*parseUserIDResponse, error) {
	if userID == "" {
		return nil, fmt.Errorf("missing userID")
	}

	// Split the userID into substrings.
	fields := strings.Split(userID, ":")
	if len(fields) < 3 {
		return nil, fmt.Errorf("invalid number of fields in userID")
	}

	// Extract out the selector fields.

	// Use SplitN and only split into two halves. Otherwise,
	// strings.Split() might cut the selector into more than two
	// fields, if there is a '=' on the value part.
	selectorFields := strings.SplitN(fields[0], "=", 2)
	if len(selectorFields) != 2 {
		return nil, fmt.Errorf("invalid length for selector in user ID")
	}
	selectorType := strings.TrimSpace(selectorFields[0])
	selectorValue := strings.TrimSpace(selectorFields[1])
	if selectorType == "" || selectorValue == "" {
		return nil, fmt.Errorf("selector field or value of the user ID is empty")
	}

	// Get the HMAC key based on the selector type.
	hmacKey := ""
	switch selectorType {
	case selectorTypeApp:
		app, err := b.appEntry(s, selectorValue)
		if err != nil {
			return nil, err
		}
		if app == nil {
			return nil, fmt.Errorf("invalid app credential selector in user ID")
		}
		hmacKey = app.HMACKey
	case selectorTypeGroup:
		group, err := b.groupEntry(s, selectorValue)
		if err != nil {
			return nil, err
		}
		if group == nil {
			return nil, fmt.Errorf("invalid group credential in user ID")
		}
		hmacKey = group.HMACKey
	case selectorTypeGeneric:
		generic, err := b.genericEntry(s, selectorValue)
		if err != nil {
			return nil, err
		}
		if generic == nil {
			return nil, fmt.Errorf("invalid generic credential in user ID")
		}
		hmacKey = generic.HMACKey
	default:
		// TBD: Work out the case to handle specified user IDs.
		return nil, fmt.Errorf("invalid selector type in the user ID")
	}

	// Extract out the HMAC.
	actualHMAC := fields[len(fields)-1]

	// Remove the HMAC from the collection.
	fields = fields[:len(fields)-1]

	// Join the rest of the items again.
	plaintext := strings.Join(fields, ":")

	// Create the HMAC of the plaintext part.
	computedHMAC, err := createHMACBase64(hmacKey, plaintext)
	if err != nil {
		return nil, err
	}

	// Return the authentication status and provide information to fetch
	// the authorization data.
	return &parseUserIDResponse{
		Verified:      subtle.ConstantTimeCompare([]byte(actualHMAC), []byte(computedHMAC)) == 1,
		SelectorType:  selectorType,
		SelectorValue: selectorValue,
	}, nil
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
	//key := fmt.Sprintf("%s%s", selectorType, selectorValue)
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
