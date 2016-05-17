package appgroup

import (
	"testing"

	"github.com/hashicorp/vault/logical"
)

func TestBackend_generic_login(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)
	createApp(t, b, storage, "app1")
	createGroup(t, b, storage, "group1", "app1")

	genericCredsData := map[string]interface{}{
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
		Data:      genericCredsData,
	}

	resp, err = b.HandleRequest(genericCredsReq)
	failOnError(t, resp, err)
}

func TestBackend_group_login(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	createApp(t, b, storage, "app1")
	createGroup(t, b, storage, "group1", "app1")

	groupCredsReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "group/group1/creds",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(groupCredsReq)
	failOnError(t, resp, err)

	loginData := map[string]interface{}{
		"selector": "group/group1",
		"user_id":  resp.Data["user_id"],
	}
	loginReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      loginData,
	}
	resp, err = b.HandleRequest(loginReq)
	failOnError(t, resp, err)
	if resp.Auth == nil {
		t.Fatalf("expected a non-nil auth object in the response")
	}
}

func TestBackend_app_login(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	createApp(t, b, storage, "app1")

	appCredsReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "app/app1/creds",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(appCredsReq)
	failOnError(t, resp, err)

	loginData := map[string]interface{}{
		"selector": "app/app1",
		"user_id":  resp.Data["user_id"],
	}
	loginReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      loginData,
	}
	resp, err = b.HandleRequest(loginReq)
	failOnError(t, resp, err)
	if resp.Auth == nil {
		t.Fatalf("expected a non-nil auth object in the response")
	}
}

func createApp(t *testing.T, b *backend, s logical.Storage, appName string) {
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
		Path:      "app/" + appName,
		Storage:   s,
		Data:      appData,
	}

	resp, err := b.HandleRequest(appReq)
	failOnError(t, resp, err)
}

func createGroup(t *testing.T, b *backend, s logical.Storage, groupName, apps string) {
	groupData := map[string]interface{}{
		"apps":                apps,
		"additional_policies": "a,b,c,d",
		"num_uses":            10,
		"userid_ttl":          300,
		"token_ttl":           400,
		"token_max_ttl":       500,
		"wrapped":             200,
	}
	groupReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "group/" + groupName,
		Storage:   s,
		Data:      groupData,
	}

	resp, err := b.HandleRequest(groupReq)
	failOnError(t, resp, err)
}
