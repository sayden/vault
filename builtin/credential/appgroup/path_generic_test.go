package appgroup

import (
	"testing"

	"github.com/hashicorp/vault/logical"
)

func TestBackend_generic_creds(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	appData := map[string]interface{}{
		"policies":      "p,q,r,s",
		"num_uses":      10,
		"userid_ttl":    300,
		"token_ttl":     400,
		"token_max_ttl": 500,
		"wrapped":       200,
	}
	appReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "app/app1",
		Storage:   storage,
		Data:      appData,
	}

	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)

	groupData := map[string]interface{}{
		"apps":                "app1",
		"additional_policies": "t,u,v,w",
		"num_uses":            11,
		"userid_ttl":          301,
		"token_ttl":           401,
		"token_max_ttl":       501,
		"wrapped":             201,
	}

	groupReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "group/group1",
		Storage:   storage,
		Data:      groupData,
	}

	resp, err = b.HandleRequest(groupReq)
	failOnError(t, resp, err)

	genericData := map[string]interface{}{
		"groups":              "group1",
		"apps":                "app1",
		"additional_policies": "x,y,z",
		"num_uses":            122,
		"userid_ttl":          302,
		"token_ttl":           402,
		"token_max_ttl":       502,
		"wrapped":             202,
	}

	genericCredsReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "generic/creds",
		Storage:   storage,
		Data:      genericData,
	}
	resp, err = b.HandleRequest(genericCredsReq)
	failOnError(t, resp, err)
	if resp.Data["user_id"].(string) == "" {
		t.Fatalf("failed to generate user_id")
	}

	genericCredsReq.Path = "generic/creds-specific"
	genericData["user_id"] = "abcd123"
	resp, err = b.HandleRequest(genericCredsReq)
	failOnError(t, resp, err)
	if resp != nil {
		t.Fatalf("failed to set specific user_id to generic")
	}
}
