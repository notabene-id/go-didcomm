package didcomm

import (
	"context"
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// Verify InMemorySecretsStore implements CryptoOperations.
var _ CryptoOperations = (*InMemorySecretsStore)(nil)

func TestInMemorySecretsStore_StoreAndSign(t *testing.T) {
	store := NewInMemorySecretsStore()
	ctx := context.Background()

	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := kp.SigningJWK.Set(jwk.KeyIDKey, "sig-key-1"); err != nil {
		t.Fatal(err)
	}
	if err := kp.EncryptionJWK.Set(jwk.KeyIDKey, "enc-key-1"); err != nil {
		t.Fatal(err)
	}

	store.Store(kp)

	// Sign with stored key
	hdrs := jws.NewHeaders()
	signed, err := store.Sign(ctx, "sig-key-1", []byte(`test`), hdrs)
	if err != nil {
		t.Fatal(err)
	}
	if len(signed) == 0 {
		t.Fatal("signed should not be empty")
	}
}

func TestInMemorySecretsStore_KeyNotFound(t *testing.T) {
	store := NewInMemorySecretsStore()
	ctx := context.Background()

	_, err := store.Sign(ctx, "nonexistent", []byte(`test`), jws.NewHeaders())
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}

	_, err = store.Decrypt(ctx, "nonexistent", []byte(`jwe`))
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestInMemorySecretsStore_StoreKey(t *testing.T) {
	store := NewInMemorySecretsStore()
	ctx := context.Background()

	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := kp.SigningJWK.Set(jwk.KeyIDKey, "my-key"); err != nil {
		t.Fatal(err)
	}

	store.StoreKey(kp.SigningJWK)

	// Should be able to sign with the stored key
	hdrs := jws.NewHeaders()
	signed, err := store.Sign(ctx, "my-key", []byte(`test`), hdrs)
	if err != nil {
		t.Fatal(err)
	}
	if len(signed) == 0 {
		t.Fatal("signed should not be empty")
	}
}

func TestInMemorySecretsStore_ConcurrentAccess(t *testing.T) {
	store := NewInMemorySecretsStore()
	ctx := context.Background()

	done := make(chan struct{})
	for range 10 {
		go func() {
			defer func() { done <- struct{}{} }()
			kp, err := GenerateKeyPair()
			if err != nil {
				t.Error(err)
				return
			}
			if err := kp.SigningJWK.Set(jwk.KeyIDKey, "concurrent-key"); err != nil {
				t.Error(err)
				return
			}
			store.Store(kp)
		}()
	}
	for range 10 {
		<-done
	}

	// Should be able to sign
	hdrs := jws.NewHeaders()
	_, err := store.Sign(ctx, "concurrent-key", []byte(`test`), hdrs)
	if err != nil {
		t.Fatal(err)
	}
}

func TestInMemorySecretsStore_SignAndDecryptRoundTrip(t *testing.T) {
	_, aliceKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	_, bobKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	aliceStore := NewInMemorySecretsStore()
	aliceStore.Store(aliceKP)
	bobStore := NewInMemorySecretsStore()
	bobStore.Store(bobKP)

	ctx := context.Background()

	// Alice signs
	aliceSignKID, _ := aliceKP.SigningJWK.KeyID()
	hdrs, err := buildSigningHeaders(aliceSignKID)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := aliceStore.Sign(ctx, aliceSignKID, []byte(`{"data":"secret"}`), hdrs)
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt for Bob
	bobEncPub, err := bobKP.EncryptionPublicJWK()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := anoncrypt(signed, []jwk.Key{bobEncPub})
	if err != nil {
		t.Fatal(err)
	}

	// Bob decrypts
	bobEncKID, _ := bobKP.EncryptionJWK.KeyID()
	decrypted, err := bobStore.Decrypt(ctx, bobEncKID, encrypted)
	if err != nil {
		t.Fatal(err)
	}

	// Verify Alice's signature
	alicePub, _ := aliceKP.SigningPublicJWK()
	payload, err := verifySignature(decrypted, alicePub)
	if err != nil {
		t.Fatal(err)
	}

	if string(payload) != `{"data":"secret"}` {
		t.Fatalf("payload = %s", payload)
	}
}
