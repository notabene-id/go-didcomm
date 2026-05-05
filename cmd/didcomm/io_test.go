package main

import (
	"os"
	"path/filepath"
	"testing"

	didcomm "github.com/Notabene-id/go-didcomm"
)

func TestReadMessageInput_Inline(t *testing.T) {
	data, err := readMessageInput(`{"id":"1"}`)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"id":"1"}` {
		t.Fatalf("got %s", data)
	}
}

func TestReadMessageInput_File(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "msg.json")
	if err := os.WriteFile(p, []byte(`{"id":"2"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	data, err := readMessageInput("@" + p)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"id":"2"}` {
		t.Fatalf("got %s", data)
	}
}

func TestReadMessageInput_FileNotFound(t *testing.T) {
	_, err := readMessageInput("@/nonexistent/file.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestMarshalUnmarshalDIDDoc_RoundTrip(t *testing.T) {
	doc, _, err := didcomm.GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	data, err := marshalDIDDoc(doc)
	if err != nil {
		t.Fatal(err)
	}

	doc2, err := unmarshalDIDDoc(data)
	if err != nil {
		t.Fatal(err)
	}

	if doc.ID != doc2.ID {
		t.Fatalf("ID mismatch: %s != %s", doc.ID, doc2.ID)
	}
	if len(doc2.Authentication) != 1 {
		t.Fatalf("expected 1 authentication key, got %d", len(doc2.Authentication))
	}
	if len(doc2.KeyAgreement) != 1 {
		t.Fatalf("expected 1 key agreement key, got %d", len(doc2.KeyAgreement))
	}
	if doc2.Authentication[0].ID != doc.Authentication[0].ID {
		t.Fatalf("auth key ID mismatch")
	}
	if doc2.KeyAgreement[0].ID != doc.KeyAgreement[0].ID {
		t.Fatalf("key agreement key ID mismatch")
	}
	if doc2.Authentication[0].PublicKey == nil {
		t.Fatal("authentication public key is nil after unmarshal")
	}
	if doc2.KeyAgreement[0].PublicKey == nil {
		t.Fatal("key agreement public key is nil after unmarshal")
	}
}

func TestMarshalUnmarshalDIDDoc_WithService(t *testing.T) {
	doc, _, err := didcomm.GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	doc.Service = []didcomm.Service{
		{ID: doc.ID + "#didcomm", Type: "DIDCommMessaging", ServiceEndpoint: "https://example.com"},
	}

	data, err := marshalDIDDoc(doc)
	if err != nil {
		t.Fatal(err)
	}

	doc2, err := unmarshalDIDDoc(data)
	if err != nil {
		t.Fatal(err)
	}

	if len(doc2.Service) != 1 {
		t.Fatalf("expected 1 service, got %d", len(doc2.Service))
	}
	if doc2.Service[0].ServiceEndpoint != "https://example.com" {
		t.Fatalf("service endpoint mismatch: %s", doc2.Service[0].ServiceEndpoint)
	}
}

func TestUnmarshalDIDDoc_InvalidJSON(t *testing.T) {
	_, err := unmarshalDIDDoc([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestMarshalKeyPair(t *testing.T) {
	_, kp, err := didcomm.GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	data, err := marshalKeyPair(kp)
	if err != nil {
		t.Fatal(err)
	}

	// Verify it's valid JWK Set JSON
	if len(data) == 0 {
		t.Fatal("empty key set output")
	}

	// Should be able to load it back
	dir := t.TempDir()
	p := filepath.Join(dir, "keys.json")
	writeErr := os.WriteFile(p, data, 0o600)
	if writeErr != nil {
		t.Fatal(writeErr)
	}

	store, err := loadKeyFile(p)
	if err != nil {
		t.Fatal(err)
	}

	// Verify both keys are loadable
	if store == nil {
		t.Fatal("nil store")
	}
}

func TestLoadKeyFile_NotFound(t *testing.T) {
	_, err := loadKeyFile("/nonexistent/keys.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadKeyFile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(p, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := loadKeyFile(p)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadDIDDocs(t *testing.T) {
	doc1, _, err := didcomm.GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	doc2, _, err := didcomm.GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	p1 := filepath.Join(dir, "doc1.json")
	p2 := filepath.Join(dir, "doc2.json")

	data1, _ := marshalDIDDoc(doc1)
	data2, _ := marshalDIDDoc(doc2)

	os.WriteFile(p1, data1, 0o644)
	os.WriteFile(p2, data2, 0o644)

	resolver, err := loadDIDDocs(p1 + "," + p2)
	if err != nil {
		t.Fatal(err)
	}

	if resolver == nil {
		t.Fatal("nil resolver")
	}
}

func TestLoadDIDDocs_Empty(t *testing.T) {
	resolver, err := loadDIDDocs("")
	if err != nil {
		t.Fatal(err)
	}
	if resolver == nil {
		t.Fatal("nil resolver for empty paths")
	}
}

func TestDetectContentType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"JWE compact", "a.b.c.d.e", "application/didcomm-encrypted+json"},
		{"JWS compact", "a.b.c", "application/didcomm-signed+json"},
		{"plain JSON", `{"id":"1"}`, "application/didcomm-plain+json"},
		{"JWE JSON", `{"ciphertext":"abc","recipients":[]}`, "application/didcomm-encrypted+json"},
		{"JWS JSON flattened", `{"payload":"abc","protected":"def","signature":"ghi"}`, "application/didcomm-signed+json"},
		{"JWS JSON general", `{"payload":"abc","signatures":[{"protected":"def","signature":"ghi"}]}`, "application/didcomm-signed+json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectContentType([]byte(tt.input))
			if got != tt.expected {
				t.Fatalf("got %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestParseMessage(t *testing.T) {
	msg, err := parseMessage([]byte(`{"id":"1","type":"test","body":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if msg.ID != "1" {
		t.Fatalf("got ID %s", msg.ID)
	}
	if msg.Type != "test" {
		t.Fatalf("got Type %s", msg.Type)
	}
}

func TestParseMessage_Invalid(t *testing.T) {
	_, err := parseMessage([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
