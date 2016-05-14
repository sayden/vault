package appgroup

import (
	"log"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/mitchellh/mapstructure"
)

func TestBackend_app_creds(t *testing.T) {
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

	appCredsReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "app/app1/creds",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(appCredsReq)
	failOnError(t, resp, err)
	if resp.Data["user_id"].(string) == "" {
		t.Fatalf("failed to generate user_id")
	}

	appCredsReq.Path = "app/app1/creds-specific"
	appCredsSpecificData := map[string]interface{}{
		"user_id": "abcd123",
	}
	appCredsReq.Data = appCredsSpecificData
	appCredsReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(appCredsReq)
	failOnError(t, resp, err)
	if resp != nil {
		t.Fatalf("failed to set specific user_id to app")
	}
}

func TestBackend_app_CRUD(t *testing.T) {
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

	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)

	expected := map[string]interface{}{
		"policies":      []string{"default", "p", "q", "r", "s"},
		"num_uses":      10,
		"userid_ttl":    300,
		"token_ttl":     400,
		"token_max_ttl": 500,
		"wrapped":       200,
	}
	var expectedStruct appStorageEntry
	err = mapstructure.Decode(expected, &expectedStruct)
	if err != nil {
		t.Fatal(err)
	}

	var actualStruct appStorageEntry
	err = mapstructure.Decode(resp.Data, &actualStruct)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expectedStruct, actualStruct) {
		log.Printf("bad:\nexpected:%#v\nactual:%#v\n", expectedStruct, actualStruct)
	}

	appData = map[string]interface{}{
		"policies":      "a,b,c,d",
		"num_uses":      100,
		"userid_ttl":    3000,
		"token_ttl":     4000,
		"token_max_ttl": 5000,
		"wrapped":       2000,
	}
	appReq.Data = appData
	appReq.Operation = logical.UpdateOperation

	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)

	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)

	expected = map[string]interface{}{
		"policies":      []string{"a", "b", "c", "d", "default"},
		"num_uses":      100,
		"userid_ttl":    3000,
		"token_ttl":     4000,
		"token_max_ttl": 5000,
		"wrapped":       2000,
	}
	err = mapstructure.Decode(expected, &expectedStruct)
	if err != nil {
		t.Fatal(err)
	}

	err = mapstructure.Decode(resp.Data, &actualStruct)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expectedStruct, actualStruct) {
		log.Printf("bad:\nexpected:%#v\nactual:%#v\n", expectedStruct, actualStruct)
	}

	// RUD for policiess field
	appReq.Path = "app/app1/policies"
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	appReq.Data = map[string]interface{}{"policies": "a1,b1,c1,d1"}
	appReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	if !reflect.DeepEqual(resp.Data["policies"].([]string), []string{"a1", "b1", "c1", "d1", "default"}) {
		t.Fatalf("bad: policies: actual:%s\n", resp.Data["policies"].([]string))
	}
	appReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	if resp.Data["policies"].([]string) != nil {
		t.Fatalf("expected value to be reset")
	}

	// RUD for num-uses field
	appReq.Path = "app/app1/num-uses"
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	appReq.Data = map[string]interface{}{"num_uses": 200}
	appReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	if resp.Data["num_uses"].(int) != 200 {
		t.Fatalf("bad: num_uses: expected:200 actual:%d\n", resp.Data["num_uses"].(int))
	}
	appReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	if resp.Data["num_uses"].(int) != 0 {
		t.Fatalf("expected value to be reset")
	}

	// RUD for userid_ttl field
	appReq.Path = "app/app1/userid-ttl"
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	appReq.Data = map[string]interface{}{"userid_ttl": 3001}
	appReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	if resp.Data["userid_ttl"].(time.Duration) != 3001 {
		t.Fatalf("bad: userid_ttl: expected:3001 actual:%d\n", resp.Data["userid_ttl"].(time.Duration))
	}
	appReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	if resp.Data["userid_ttl"].(time.Duration) != 0 {
		t.Fatalf("expected value to be reset")
	}

	// RUD for token_ttl field
	appReq.Path = "app/app1/token-ttl"
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	appReq.Data = map[string]interface{}{"token_ttl": 4001}
	appReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	if resp.Data["token_ttl"].(time.Duration) != 4001 {
		t.Fatalf("bad: token_ttl: expected:4001 actual:%d\n", resp.Data["token_ttl"].(time.Duration))
	}
	appReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	if resp.Data["token_ttl"].(time.Duration) != 0 {
		t.Fatalf("expected value to be reset")
	}

	// RUD for token_max_ttl field
	appReq.Path = "app/app1/token-max-ttl"
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	appReq.Data = map[string]interface{}{"token_max_ttl": 5001}
	appReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	if resp.Data["token_max_ttl"].(time.Duration) != 5001 {
		t.Fatalf("bad: token_max_ttl: expected:5001 actual:%d\n", resp.Data["token_max_ttl"].(time.Duration))
	}
	appReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	if resp.Data["token_max_ttl"].(time.Duration) != 0 {
		t.Fatalf("expected value to be reset")
	}

	// RUD for wrapped field
	appReq.Path = "app/app1/wrapped"
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	appReq.Data = map[string]interface{}{"wrapped": 2001}
	appReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	if resp.Data["wrapped"].(time.Duration) != 2001 {
		t.Fatalf("bad: wrapped: expected:2001 actual:%d\n", resp.Data["wrapped"].(time.Duration))
	}
	appReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	if resp.Data["wrapped"].(time.Duration) != 0 {
		t.Fatalf("expected value to be reset")
	}

	// Delete test for app
	appReq.Path = "app/app1"
	appReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)

	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	failOnError(t, resp, err)
	if resp != nil {
		t.Fatalf("expected a nil response")
	}
}
