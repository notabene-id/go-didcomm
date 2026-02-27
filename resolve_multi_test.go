package didcomm

import (
	"context"
	"errors"
	"testing"
)

func TestMultiResolver_DIDKey(t *testing.T) {
	multi, _ := DefaultResolver()

	doc, _, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	resolved, err := multi.Resolve(context.Background(), doc.ID)
	if err != nil {
		t.Fatalf("resolve did:key: %v", err)
	}
	if resolved.ID != doc.ID {
		t.Fatalf("ID mismatch: %s != %s", resolved.ID, doc.ID)
	}
}

func TestMultiResolver_Fallback(t *testing.T) {
	multi, mem := DefaultResolver()

	// Store a custom document
	doc := &DIDDocument{
		ID: "did:example:custom",
	}
	mem.Store(doc)

	resolved, err := multi.Resolve(context.Background(), "did:example:custom")
	if err != nil {
		t.Fatalf("resolve custom: %v", err)
	}
	if resolved.ID != "did:example:custom" {
		t.Fatalf("ID mismatch: %s", resolved.ID)
	}
}

func TestMultiResolver_FallbackOverride(t *testing.T) {
	multi, mem := DefaultResolver()

	// Store a did:key document manually — it should take priority over DIDKeyResolver
	doc, _, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	doc.Service = []Service{{ID: "custom", Type: "test", ServiceEndpoint: "http://test"}}
	mem.Store(doc)

	resolved, err := multi.Resolve(context.Background(), doc.ID)
	if err != nil {
		t.Fatalf("resolve override: %v", err)
	}
	// Should have the custom service from our override, not the bare DIDKeyResolver result
	if len(resolved.Service) != 1 {
		t.Fatalf("expected 1 service from override, got %d", len(resolved.Service))
	}
}

func TestMultiResolver_UnknownMethod(t *testing.T) {
	multi, _ := DefaultResolver()

	_, err := multi.Resolve(context.Background(), "did:unknown:something")
	if !errors.Is(err, ErrDIDNotFound) {
		t.Fatalf("expected ErrDIDNotFound, got %v", err)
	}
}

func TestMultiResolver_InvalidDID(t *testing.T) {
	multi, _ := DefaultResolver()

	_, err := multi.Resolve(context.Background(), "not-a-did")
	if !errors.Is(err, ErrDIDNotFound) {
		t.Fatalf("expected ErrDIDNotFound, got %v", err)
	}
}

func TestExtractDIDMethod(t *testing.T) {
	tests := []struct {
		did    string
		method string
	}{
		{"did:key:z6Mk...", "did:key"},
		{"did:web:example.com", "did:web"},
		{"did:web:example.com:path", "did:web"},
		{"did:example:123", "did:example"},
		{"not-a-did", ""},
		{"did:nocolon", ""},
	}

	for _, tt := range tests {
		t.Run(tt.did, func(t *testing.T) {
			got := extractDIDMethod(tt.did)
			if got != tt.method {
				t.Fatalf("got %q, want %q", got, tt.method)
			}
		})
	}
}

func TestDefaultResolver_Integration(t *testing.T) {
	// Full round-trip: generate keys, create client with DefaultResolver, pack/unpack
	aliceDoc, aliceKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	bobDoc, bobKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	multi, _ := DefaultResolver()
	secrets := NewInMemorySecretsStore()
	secrets.Store(aliceKP)
	secrets.Store(bobKP)

	client := NewClient(multi, secrets)
	ctx := context.Background()

	msg := &Message{
		ID:   "integration-1",
		Type: "https://example.com/test",
		From: aliceDoc.ID,
		To:   []string{bobDoc.ID},
		Body: []byte(`{}`),
	}

	packed, err := client.PackAuthcrypt(ctx, msg)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	result, err := client.Unpack(ctx, packed)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}

	if result.Message.ID != "integration-1" {
		t.Fatalf("message ID: %s", result.Message.ID)
	}
	if !result.Encrypted || !result.Signed {
		t.Fatal("expected encrypted+signed")
	}
}

func TestDefaultResolver_SignedRoundTrip(t *testing.T) {
	doc, kp, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	multi, _ := DefaultResolver()
	secrets := NewInMemorySecretsStore()
	secrets.Store(kp)

	client := NewClient(multi, secrets)
	ctx := context.Background()

	msg := &Message{
		ID:   "signed-1",
		Type: "https://example.com/test",
		From: doc.ID,
		Body: []byte(`{}`),
	}

	packed, err := client.PackSigned(ctx, msg)
	if err != nil {
		t.Fatalf("pack signed: %v", err)
	}

	result, err := client.Unpack(ctx, packed)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}

	if !result.Signed {
		t.Fatal("expected signed")
	}
	if result.Encrypted {
		t.Fatal("expected not encrypted")
	}
}
