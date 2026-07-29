package estapi

import (
	"net/http"
	"strings"
	"testing"
)

func TestHandleSimpleEnroll_OversizedBodyRejected(t *testing.T) {
	tc := newTestCA(t)
	ts := newTestServer(t, tc, nil)
	leafCert, leafKey := tc.issueLeaf(t, "existing-client.example.test")
	client := clientFor(t, ts, leafCert, leafKey)

	oversized := strings.NewReader(strings.Repeat("A", maxCSRBodyBytes+1))
	resp, err := client.Post(ts.URL+"/.well-known/est/simpleenroll", contentTypePKCS10, oversized)
	if err != nil {
		t.Fatalf("POST /simpleenroll: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}
