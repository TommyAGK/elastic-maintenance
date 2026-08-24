package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCredentialRequestFieldContract(t *testing.T) {
	encoded, err := json.Marshal(ConfirmedMutationRequest{Confirm: true})
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"confirm":true}` {
		t.Fatalf("encoded=%s", encoded)
	}
	credential, _ := json.Marshal(CredentialPutRequest{APIKey: "sentinel", CACertificatePEM: "certificate"})
	if !strings.Contains(string(credential), `"apiKey"`) || !strings.Contains(string(credential), `"caCertificatePem"`) {
		t.Fatalf("encoded=%s", credential)
	}
}
