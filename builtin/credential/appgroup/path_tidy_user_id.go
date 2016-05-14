package appgroup

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathTidyUserID(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "tidy/user-id$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathTidyUserIDUpdate,
		},

		HelpSynopsis:    pathTidyUserIDSyn,
		HelpDescription: pathTidyUserIDDesc,
	}
}

// tidyUserID is used to delete entries in the whitelist that are expired.
func (b *backend) tidyUserID(s logical.Storage) error {
	grabbed := atomic.CompareAndSwapUint32(&b.tidyUserIDCASGuard, 0, 1)
	if grabbed {
		defer atomic.StoreUint32(&b.tidyUserIDCASGuard, 0)
	} else {
		return fmt.Errorf("user ID tidy operation already running")
	}

	userIDs, err := s.List("userid/")
	if err != nil {
		return err
	}

	for _, userID := range userIDs {
		userIDEntry, err := s.Get("userID/" + userID)
		if err != nil {
			return fmt.Errorf("error fetching user ID %s: %s", userID, err)
		}

		if userIDEntry == nil {
			return fmt.Errorf("entry for user ID %s is nil", userID)
		}

		if userIDEntry.Value == nil || len(userIDEntry.Value) == 0 {
			return fmt.Errorf("found entry for user ID %s but actual user ID is empty", userID)
		}

		var result userIDStorageEntry
		if err := userIDEntry.DecodeJSON(&result); err != nil {
			return err
		}

		if time.Now().UTC().After(result.ExpirationTime) {
			if err := s.Delete("userid/" + userID); err != nil {
				return fmt.Errorf("error deleting user ID %s from storage: %s", userID, err)
			}
		}
	}

	return nil
}

// pathTidyUserIDUpdate is used to delete the expired UserID entries
func (b *backend) pathTidyUserIDUpdate(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, b.tidyUserID(req.Storage)
}

const pathTidyUserIDSyn = `
`

const pathTidyUserIDDesc = `
`
