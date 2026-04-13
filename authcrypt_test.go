package didcomm

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// signAndEncrypt is a test helper that performs authcrypt through CryptoOperations.
func signAndEncrypt(t *testing.T, signer *InMemorySecretsStore, signingKID string, payload []byte, recipientKeys []jwk.Key) []byte {
	t.Helper()
	hdrs, err := buildSigningHeaders(signingKID)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(context.Background(), signingKID, payload, hdrs)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := authcryptEnvelope(signed, signingKID, recipientKeys)
	if err != nil {
		t.Fatal(err)
	}
	return encrypted
}

func TestAuthcryptRoundTrip(t *testing.T) {
	_, aliceKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	_, bobKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	msg := &Message{
		ID:   "msg-1",
		Type: "https://example.com/test",
		Body: json.RawMessage(`{"hello":"world"}`),
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	aliceSecrets := NewInMemorySecretsStore()
	aliceSecrets.Store(aliceKP)
	aliceSignKID, _ := aliceKP.SigningJWK.KeyID()

	bobEncPub, err := bobKP.EncryptionPublicJWK()
	if err != nil {
		t.Fatal(err)
	}

	encrypted := signAndEncrypt(t, aliceSecrets, aliceSignKID, payload, []jwk.Key{bobEncPub})
	if len(encrypted) == 0 {
		t.Fatal("encrypted message should not be empty")
	}

	// Decrypt with Bob's CryptoOperations
	bobSecrets := NewInMemorySecretsStore()
	bobSecrets.Store(bobKP)
	bobEncKID, _ := bobKP.EncryptionJWK.KeyID()

	decrypted, err := bobSecrets.Decrypt(context.Background(), bobEncKID, encrypted)
	if err != nil {
		t.Fatal(err)
	}

	// Verify signature with Alice's public key
	aliceSigPub, err := aliceKP.SigningPublicJWK()
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifySignature(decrypted, aliceSigPub)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Message
	if err := json.Unmarshal(verified, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ID != "msg-1" {
		t.Fatalf("expected ID=msg-1, got %s", decoded.ID)
	}
}

func TestAuthcrypt_WrongSenderKey(t *testing.T) {
	_, aliceKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	_, bobKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	_, eveKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	aliceSecrets := NewInMemorySecretsStore()
	aliceSecrets.Store(aliceKP)
	aliceSignKID, _ := aliceKP.SigningJWK.KeyID()

	bobEncPub, _ := bobKP.EncryptionPublicJWK()
	encrypted := signAndEncrypt(t, aliceSecrets, aliceSignKID, []byte(`{"id":"1","type":"t","body":{}}`), []jwk.Key{bobEncPub})

	bobSecrets := NewInMemorySecretsStore()
	bobSecrets.Store(bobKP)
	bobEncKID, _ := bobKP.EncryptionJWK.KeyID()
	decrypted, err := bobSecrets.Decrypt(context.Background(), bobEncKID, encrypted)
	if err != nil {
		t.Fatal(err)
	}

	// Verify with Eve's key — should fail
	eveSigPub, _ := eveKP.SigningPublicJWK()
	_, err = verifySignature(decrypted, eveSigPub)
	if err == nil {
		t.Fatal("verification should fail with wrong sender key")
	}
}

func TestAuthcrypt_WrongRecipientKey(t *testing.T) {
	_, aliceKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	_, bobKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	_, eveKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	aliceSecrets := NewInMemorySecretsStore()
	aliceSecrets.Store(aliceKP)
	aliceSignKID, _ := aliceKP.SigningJWK.KeyID()

	bobEncPub, _ := bobKP.EncryptionPublicJWK()
	encrypted := signAndEncrypt(t, aliceSecrets, aliceSignKID, []byte(`{"id":"1","type":"t","body":{}}`), []jwk.Key{bobEncPub})

	// Decrypt with Eve's key — should fail
	eveSecrets := NewInMemorySecretsStore()
	eveSecrets.Store(eveKP)
	eveEncKID, _ := eveKP.EncryptionJWK.KeyID()
	_, err = eveSecrets.Decrypt(context.Background(), eveEncKID, encrypted)
	if err == nil {
		t.Fatal("decryption should fail with wrong recipient key")
	}
}

func TestAuthcryptEnvelope_NoRecipients(t *testing.T) {
	_, err := authcryptEnvelope([]byte(`signed-jws`), "kid", nil)
	if !errors.Is(err, ErrNoRecipients) {
		t.Fatalf("expected ErrNoRecipients, got %v", err)
	}
}

func TestAuthcrypt_MultipleRecipients(t *testing.T) {
	_, aliceKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	_, bob1KP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	_, bob2KP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	aliceSecrets := NewInMemorySecretsStore()
	aliceSecrets.Store(aliceKP)
	aliceSignKID, _ := aliceKP.SigningJWK.KeyID()

	bob1EncPub, _ := bob1KP.EncryptionPublicJWK()
	bob2EncPub, _ := bob2KP.EncryptionPublicJWK()

	payload := []byte(`{"id":"1","type":"t","body":{}}`)
	encrypted := signAndEncrypt(t, aliceSecrets, aliceSignKID, payload, []jwk.Key{bob1EncPub, bob2EncPub})

	aliceSigPub, _ := aliceKP.SigningPublicJWK()
	ctx := context.Background()

	// Both should decrypt and verify
	bob1Secrets := NewInMemorySecretsStore()
	bob1Secrets.Store(bob1KP)
	bob1EncKID, _ := bob1KP.EncryptionJWK.KeyID()
	dec1, err := bob1Secrets.Decrypt(ctx, bob1EncKID, encrypted)
	if err != nil {
		t.Fatal("bob1 decrypt:", err)
	}
	verified1, err := verifySignature(dec1, aliceSigPub)
	if err != nil {
		t.Fatal("bob1 verify:", err)
	}
	var msg1 Message
	if err := json.Unmarshal(verified1, &msg1); err != nil {
		t.Fatal(err)
	}
	if msg1.ID != "1" {
		t.Fatalf("bob1: expected ID=1, got %s", msg1.ID)
	}

	bob2Secrets := NewInMemorySecretsStore()
	bob2Secrets.Store(bob2KP)
	bob2EncKID, _ := bob2KP.EncryptionJWK.KeyID()
	dec2, err := bob2Secrets.Decrypt(ctx, bob2EncKID, encrypted)
	if err != nil {
		t.Fatal("bob2 decrypt:", err)
	}
	verified2, err := verifySignature(dec2, aliceSigPub)
	if err != nil {
		t.Fatal("bob2 verify:", err)
	}
	var msg2 Message
	if err := json.Unmarshal(verified2, &msg2); err != nil {
		t.Fatal(err)
	}
	if msg2.ID != "1" {
		t.Fatalf("bob2: expected ID=1, got %s", msg2.ID)
	}
}
