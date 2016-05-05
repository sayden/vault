package appgroup

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/logical"
)

const (
	selectorTypeApp     = "app"
	selectorTypeGroup   = "group"
	selectorTypeGeneric = "generic"
)

type userIDStorageEntry struct {
	SelectorType string        `json:"selector_type" structs:"selector_type" mapstructure:"selector_type"`
	AppNames     []string      `json:"app_name" structs:"app_name" mapstructure:"app_name"`
	Policies     []string      `json:"policies" structs:"policies" mapstructure:"policies"`
	NumUses      int           `json:"num_uses" structs:"num_uses" mapstructure:"num_uses"`
	TTL          time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	MaxTTL       time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
	Wrapped      time.Duration `json:"wrapped" structs:"wrapped" mapstructure:"wrapped"`
}

type parseUserIDResponse struct {
	Verified      bool
	SelectorType  string
	SelectorValue string
}

func (b *backend) parseAndVerifyUserID(s logical.Storage, userID string) (*parseUserIDResponse, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, fmt.Errorf("missing userID")
	}

	// Split the userID into substrings.
	fields := strings.Split(userID, ":")
	if len(fields) < 3 {
		return nil, fmt.Errorf("invalid number of fields in userID")
	}

	// Extract out the selector
	selector := fields[0]
	selectorFields := strings.Split(selector, "=")
	if len(selectorFields) != 2 {
		return nil, fmt.Errorf("invalid selector in the user ID")
	}
	selectorType := strings.TrimSpace(selectorFields[0])
	selectorValue := strings.TrimSpace(selectorFields[1])
	if selectorType == "" || selectorValue == "" {
		return nil, fmt.Errorf("invalid selector in the user ID")
	}

	hmacKey := ""
	switch selectorType {
	case "app":
		app, err := appEntry(s, selectorValue)
		if err != nil {
			return nil, err
		}
		if app == nil {
			return nil, fmt.Errorf("invalid app in user ID")
		}
		hmacKey = app.HMACKey
	case "group":
		group, err := groupEntry(s, selectorValue)
		if err != nil {
			return nil, err
		}
		if group == nil {
			return nil, fmt.Errorf("invalid group in user ID")
		}
		hmacKey = group.HMACKey
	case "generic":
	default:
		return nil, fmt.Errorf("invalid selector in the user ID")
	}

	// Extract out the HMAC.
	actualHMAC := fields[len(fields)-1]

	// Remove the HMAC from the collection.
	fields = fields[:len(fields)-1]

	// Join the rest of the items again.
	plaintext := strings.Join(fields, ":")

	// Create the HMAC of the value
	computedHMAC, err := createHMACBase64(hmacKey, plaintext)
	if err != nil {
		return nil, err
	}

	entry, err := b.userIDEntry(s, selectorType, userID)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("user ID not found")
	}

	return &parseUserIDResponse{
		Verified:      subtle.ConstantTimeCompare([]byte(actualHMAC), []byte(computedHMAC)) == 1,
		SelectorType:  selectorType,
		SelectorValue: selectorValue,
	}, nil
}

func (b *backend) userIDEntry(s logical.Storage, selectorType, userID string) (*userIDStorageEntry, error) {
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
