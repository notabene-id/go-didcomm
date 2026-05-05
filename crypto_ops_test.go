package didcomm

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// sealedCrypto is a test CryptoOperations that never exposes private keys.
// It stores keys internally and only performs operations.
type sealedCrypto struct {
	keys map[string]jwk.Key
}

func newSealedCrypto() *sealedCrypto {
	return &sealedCrypto{keys: make(map[string]jwk.Key)}
}

func (s *sealedCrypto) storeKey(key jwk.Key) {
	if kid, ok := key.KeyID(); ok {
		s.keys[kid] = key
	}
}

func (s *sealedCrypto) Sign(_ context.Context, kid string, payload []byte, headers jws.Headers) ([]byte, error) {
	key, ok := s.keys[kid]
	if !ok {
		return nil, fmt.Errorf("sealed: key %s not found", kid)
	}
	signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSA(), key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return nil, fmt.Errorf("sealed: sign: %w", err)
	}
	return signed, nil
}

func (s *sealedCrypto) Decrypt(_ context.Context, kid string, encrypted []byte) ([]byte, error) {
	key, ok := s.keys[kid]
	if !ok {
		return nil, fmt.Errorf("sealed: key %s not found", kid)
	}
	decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.ECDH_ES_A256KW(), key))
	if err != nil {
		return nil, fmt.Errorf("sealed: decrypt: %w", err)
	}
	return decrypted, nil
}

func TestNewClient_SignedRoundTrip(t *testing.T) {
	aliceDoc, aliceKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	bobDoc, bobKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	// Alice uses sealed crypto — private keys never exposed via GetKey.
	aliceCrypto := newSealedCrypto()
	aliceCrypto.storeKey(aliceKP.SigningJWK)
	aliceCrypto.storeKey(aliceKP.EncryptionJWK)

	resolver, mem := DefaultResolver()
	mem.Store(aliceDoc)
	mem.Store(bobDoc)

	aliceClient := NewClient(resolver, aliceCrypto)

	msg := &Message{
		ID:   "test-signed-1",
		Type: "https://example.com/test",
		From: aliceDoc.ID,
		Body: json.RawMessage(`{"hello":"sealed"}`),
	}

	signed, err := aliceClient.PackSigned(context.Background(), msg)
	if err != nil {
		t.Fatalf("PackSigned: %v", err)
	}

	// Bob unpacks using regular client (verifies with Alice's public key from resolver).
	bobSecrets := NewInMemorySecretsStore()
	bobSecrets.Store(bobKP)
	bobClient := NewClient(resolver, bobSecrets)

	result, err := bobClient.Unpack(context.Background(), signed)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}

	if !result.Signed {
		t.Error("expected Signed=true")
	}
	if result.Encrypted {
		t.Error("expected Encrypted=false")
	}
	if result.Message.ID != "test-signed-1" {
		t.Errorf("message ID = %q, want test-signed-1", result.Message.ID)
	}
}

func TestNewClient_AnoncryptRoundTrip(t *testing.T) {
	aliceDoc, aliceKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	bobDoc, bobKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	resolver, mem := DefaultResolver()
	mem.Store(aliceDoc)
	mem.Store(bobDoc)

	// Alice encrypts using regular client (anoncrypt only needs recipient public keys).
	aliceSecrets := NewInMemorySecretsStore()
	aliceSecrets.Store(aliceKP)
	aliceClient := NewClient(resolver, aliceSecrets)

	msg := &Message{
		ID:   "test-anon-1",
		Type: "https://example.com/test",
		To:   []string{bobDoc.ID},
		Body: json.RawMessage(`{"hello":"anon-sealed"}`),
	}

	encrypted, err := aliceClient.PackAnoncrypt(context.Background(), msg)
	if err != nil {
		t.Fatalf("PackAnoncrypt: %v", err)
	}

	// Bob uses sealed crypto to decrypt.
	bobCrypto := newSealedCrypto()
	bobCrypto.storeKey(bobKP.EncryptionJWK)
	bobClient := NewClient(resolver, bobCrypto)

	result, err := bobClient.Unpack(context.Background(), encrypted)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}

	if !result.Encrypted {
		t.Error("expected Encrypted=true")
	}
	if !result.Anonymous {
		t.Error("expected Anonymous=true")
	}
	if result.Message.ID != "test-anon-1" {
		t.Errorf("message ID = %q, want test-anon-1", result.Message.ID)
	}
}

func TestNewClient_AuthcryptRoundTrip(t *testing.T) {
	aliceDoc, aliceKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	bobDoc, bobKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	resolver, mem := DefaultResolver()
	mem.Store(aliceDoc)
	mem.Store(bobDoc)

	// Alice uses sealed crypto for signing.
	aliceCrypto := newSealedCrypto()
	aliceCrypto.storeKey(aliceKP.SigningJWK)
	aliceCrypto.storeKey(aliceKP.EncryptionJWK)
	aliceClient := NewClient(resolver, aliceCrypto)

	msg := &Message{
		ID:   "test-auth-1",
		Type: "https://example.com/test",
		From: aliceDoc.ID,
		To:   []string{bobDoc.ID},
		Body: json.RawMessage(`{"hello":"auth-sealed"}`),
	}

	encrypted, err := aliceClient.PackAuthcrypt(context.Background(), msg)
	if err != nil {
		t.Fatalf("PackAuthcrypt: %v", err)
	}

	// Bob uses sealed crypto for decryption.
	bobCrypto := newSealedCrypto()
	bobCrypto.storeKey(bobKP.EncryptionJWK)
	bobClient := NewClient(resolver, bobCrypto)

	result, err := bobClient.Unpack(context.Background(), encrypted)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}

	if !result.Encrypted {
		t.Error("expected Encrypted=true")
	}
	if !result.Signed {
		t.Error("expected Signed=true")
	}
	if result.Anonymous {
		t.Error("expected Anonymous=false")
	}
	if result.Message.ID != "test-auth-1" {
		t.Errorf("message ID = %q, want test-auth-1", result.Message.ID)
	}
}

func TestNewClient_CrossCompatibility(t *testing.T) {
	// Alice uses NewClient (sealed), Bob uses NewClient (legacy).
	// They should interop.
	aliceDoc, aliceKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	bobDoc, bobKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	resolver, mem := DefaultResolver()
	mem.Store(aliceDoc)
	mem.Store(bobDoc)

	aliceCrypto := newSealedCrypto()
	aliceCrypto.storeKey(aliceKP.SigningJWK)
	aliceCrypto.storeKey(aliceKP.EncryptionJWK)
	aliceClient := NewClient(resolver, aliceCrypto)

	bobSecrets := NewInMemorySecretsStore()
	bobSecrets.Store(bobKP)
	bobClient := NewClient(resolver, bobSecrets)

	// Alice (sealed) → Bob (legacy)
	msg := &Message{
		ID:   "cross-1",
		Type: "https://example.com/test",
		From: aliceDoc.ID,
		To:   []string{bobDoc.ID},
		Body: json.RawMessage(`{"direction":"sealed-to-legacy"}`),
	}

	encrypted, err := aliceClient.PackAuthcrypt(context.Background(), msg)
	if err != nil {
		t.Fatalf("Alice PackAuthcrypt: %v", err)
	}

	result, err := bobClient.Unpack(context.Background(), encrypted)
	if err != nil {
		t.Fatalf("Bob Unpack: %v", err)
	}
	if result.Message.ID != "cross-1" {
		t.Errorf("message ID = %q, want cross-1", result.Message.ID)
	}

	// Bob (legacy) → Alice (sealed)
	msg2 := &Message{
		ID:   "cross-2",
		Type: "https://example.com/test",
		From: bobDoc.ID,
		To:   []string{aliceDoc.ID},
		Body: json.RawMessage(`{"direction":"legacy-to-sealed"}`),
	}

	encrypted2, err := bobClient.PackAuthcrypt(context.Background(), msg2)
	if err != nil {
		t.Fatalf("Bob PackAuthcrypt: %v", err)
	}

	result2, err := aliceClient.Unpack(context.Background(), encrypted2)
	if err != nil {
		t.Fatalf("Alice Unpack: %v", err)
	}
	if result2.Message.ID != "cross-2" {
		t.Errorf("message ID = %q, want cross-2", result2.Message.ID)
	}
}
