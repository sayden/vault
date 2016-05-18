package appgroup

import (
	"testing"

	"github.com/hashicorp/vault/helper/policies"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
)

func TestBackend_generic_login(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)
	createApp(t, b, storage, "app1", "a,b")
	createApp(t, b, storage, "app2", "c,d")
	createApp(t, b, storage, "app3", "e,f")
	createApp(t, b, storage, "app4", "g,h")
	createApp(t, b, storage, "app5", "i,j")
	createApp(t, b, storage, "app6", "k,l")
	createGroup(t, b, storage, "group1", "app3,app4", "m,n")
	createGroup(t, b, storage, "group2", "app5,app6", "o,p")
	createGroup(t, b, storage, "group3", "app3,app4,app5,app6", "q,r")

	genericCredsData := map[string]interface{}{
		"groups":              "group1,group2,group3",
		"apps":                "app1,app2",
		"additional_policies": "s,t",
		"num_uses":            122,
		"userid_ttl":          302,
		"token_ttl":           402,
		"token_max_ttl":       502,
		"wrap_ttl":            202,
	}

	genericCredsReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "generic/creds",
		Storage:   storage,
		Data:      genericCredsData,
	}

	resp, err = b.HandleRequest(genericCredsReq)
	failOnError(t, resp, err)

	loginData := map[string]interface{}{
		"selector": "generic",
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
	expectedPolicies := policyutil.ParsePolicies("a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t")
	if !policies.EquivalentPolicies(resp.Auth.Policies, expectedPolicies) {
		t.Fatalf("bad: auth policies: expected:%s\nactual:%s\n", expectedPolicies, resp.Auth.Policies)
	}
}

func TestBackend_group_login(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	createApp(t, b, storage, "app1", "a,b")
	createApp(t, b, storage, "app2", "c,d")
	createGroup(t, b, storage, "group1", "app1,app2", "e,f")

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

	expectedPolicies := policyutil.ParsePolicies("a,b,c,d,e,f")
	if !policies.EquivalentPolicies(resp.Auth.Policies, expectedPolicies) {
		t.Fatalf("bad: auth policies: expected:%s\nactual:%s\n", expectedPolicies, resp.Auth.Policies)
	}
}

func TestBackend_app_login(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	createApp(t, b, storage, "app1", "a,b,c")

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
