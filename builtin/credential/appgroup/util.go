package appgroup

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/helper/policyutil"
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

type validateUserIDResponse struct {
	TTL      time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	Wrapped  time.Duration `json:"wrapped" structs:"wrapped" mapstructure:"wrapped"`
	Policies []string      `json:"policies" structs:"policies" mapstructure:"policies"`
}

func (b *backend) validateUserID(s logical.Storage, userID string) (*validateUserIDResponse, error) {
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
	idEntry, err := b.userIDEntry(s, parseResp.SelectorType, userID)
	if err != nil {
		return nil, err
	}
	if idEntry == nil {
		return nil, fmt.Errorf("user ID not found")
	}

	// Based on the selector type, prepare the (effective) policies.
	// This is credential issue time, so validate the TTL and MaxTTL
	// boundaries too.
	var policies []string
	var ttl time.Duration
	var maxTTL time.Duration
	var wrapped time.Duration
	switch parseResp.SelectorType {
	case selectorTypeApp:
		app, err := appEntry(s, parseResp.SelectorValue)
		if err != nil {
			return nil, err
		}
		if app == nil {
			return nil, fmt.Errorf("app referred by the user ID does not exist")
		}
		policies = app.Policies
		ttl = app.TTL
		maxTTL = app.MaxTTL
		wrapped = app.Wrapped
	case selectorTypeGroup:
		group, err := groupEntry(s, parseResp.SelectorValue)
		if err != nil {
			return nil, err
		}
		if group == nil {
			return nil, fmt.Errorf("group referred by the user ID does not exist")
		}
		groupPolicies, err := fetchPolicies(s, group.Apps)
		if err != nil {
			return nil, err
		}
		policies = append(policies, groupPolicies...)
		policies = append(policies, group.AdditionalPolicies...)
		ttl = group.TTL
		maxTTL = group.MaxTTL
		wrapped = group.Wrapped
	case selectorTypeGeneric:
		generic, err := genericEntry(s, parseResp.SelectorValue)
		if err != nil {
			return nil, err
		}
		if generic == nil {
			return nil, fmt.Errorf("generic credential referred by the user ID does not exist")
		}
		for _, groupName := range generic.Groups {
			group, err := groupEntry(s, groupName)
			if err != nil {
				return nil, err
			}
			groupPolicies, err := fetchPolicies(s, group.Apps)
			if err != nil {
				return nil, err
			}
			policies = append(policies, groupPolicies...)
			policies = append(policies, group.AdditionalPolicies...)
		}

		for _, appName := range generic.Apps {
			app, err := appEntry(s, appName)
			if err != nil {
				return nil, err
			}
			policies = append(policies, app.Policies...)
		}
		policies = append(policies, generic.AdditionalPolicies...)
		ttl = generic.TTL
		maxTTL = generic.MaxTTL
		wrapped = generic.Wrapped
	default:
		return nil, fmt.Errorf("unknown selector type")
	}

	// Cap the ttl and max_ttl values.
	ttl, maxTTL, err = b.SanitizeTTL(ttl, maxTTL)
	if err != nil {
		return nil, err
	}

	// Although wrapped is unrelated to the ttl and max_ttl values,
	// since it is issued out of the backend, it should respect the
	// backend's boundaries.
	if wrapped > b.System().MaxLeaseTTL() {
		wrapped = b.System().MaxLeaseTTL()
	}

	return &validateUserIDResponse{
		Policies: policyutil.SanitizePolicies(policies),
		TTL:      ttl,
		Wrapped:  wrapped,
	}, nil
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
		app, err := appEntry(s, selectorValue)
		if err != nil {
			return nil, err
		}
		if app == nil {
			return nil, fmt.Errorf("invalid app credential selector in user ID")
		}
		hmacKey = app.HMACKey
	case selectorTypeGroup:
		group, err := groupEntry(s, selectorValue)
		if err != nil {
			return nil, err
		}
		if group == nil {
			return nil, fmt.Errorf("invalid group credential in user ID")
		}
		hmacKey = group.HMACKey
	case selectorTypeGeneric:
		generic, err := genericEntry(s, selectorValue)
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

func (b *backend) userIDEntry(s logical.Storage, selectorType, userID string) (*userIDStorageEntry, error) {

	// TODO: Decrement the num_uses. If it reaches 0, set it to -1.

	var result userIDStorageEntry

	entryIndex := "userid/" + selectorType + "/" + b.salt.SaltID(strings.ToLower(userID))
	if entry, err := s.Get(entryIndex); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) setUserIDEntry(s logical.Storage, selectorType, userID string, userIDEntry *userIDStorageEntry) error {

	// TODO: Start an expiration timer based on the TTL value.

	entryIndex := "userid/" + selectorType + "/" + b.salt.SaltID(strings.ToLower(userID))
	entry, err := logical.StorageEntryJSON(entryIndex, userIDEntry)
	if err != nil {
		return err
	}

	return s.Put(entry)
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
func fetchPolicies(s logical.Storage, apps []string) ([]string, error) {
	var policies []string
	for _, appName := range apps {
		app, err := appEntry(s, appName)
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
