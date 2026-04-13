package didcomm

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jws"
)

func TestSignAndVerify(t *testing.T) {
	_, kp, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	secrets := NewInMemorySecretsStore()
	secrets.Store(kp)
	kid, _ := kp.SigningJWK.KeyID()

	payload := []byte(`{"id":"1","type":"test","body":{}}`)

	hdrs, err := buildSigningHeaders(kid)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := secrets.Sign(context.Background(), kid, payload, hdrs)
	if err != nil {
		t.Fatal(err)
	}

	if len(signed) == 0 {
		t.Fatal("signed should not be empty")
	}

	pubKey, err := kp.SigningPublicJWK()
	if err != nil {
		t.Fatal(err)
	}

	verified, err := verifySignature(signed, pubKey)
	if err != nil {
		t.Fatal(err)
	}

	if string(verified) != string(payload) {
		t.Fatalf("payload mismatch: got %s", verified)
	}
}

func TestSign_IncludesHeaders(t *testing.T) {
	_, kp, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	secrets := NewInMemorySecretsStore()
	secrets.Store(kp)
	kid, _ := kp.SigningJWK.KeyID()

	hdrs, err := buildSigningHeaders(kid)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := secrets.Sign(context.Background(), kid, []byte(`{}`), hdrs)
	if err != nil {
		t.Fatal(err)
	}

	parsedHdrs, err := parseJWSHeaders(signed)
	if err != nil {
		t.Fatal(err)
	}

	gotKID, ok := parsedHdrs.KeyID()
	if !ok || gotKID != kid {
		t.Fatalf("kid = %q, want %q", gotKID, kid)
	}

	var typ string
	if err := parsedHdrs.Get(jws.TypeKey, &typ); err != nil {
		t.Fatal(err)
	}
	if typ != "application/didcomm-signed+json" {
		t.Fatalf("typ = %q", typ)
	}
}

func TestVerifySignature_WrongKey(t *testing.T) {
	_, kp1, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	_, kp2, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	secrets := NewInMemorySecretsStore()
	secrets.Store(kp1)
	kid, _ := kp1.SigningJWK.KeyID()

	hdrs, err := buildSigningHeaders(kid)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := secrets.Sign(context.Background(), kid, []byte(`{}`), hdrs)
	if err != nil {
		t.Fatal(err)
	}

	wrongPub, _ := kp2.SigningPublicJWK()
	_, err = verifySignature(signed, wrongPub)
	if err == nil {
		t.Fatal("verification should fail with wrong key")
	}
}

func TestParseJWSHeaders(t *testing.T) {
	_, kp, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	secrets := NewInMemorySecretsStore()
	secrets.Store(kp)
	kid, _ := kp.SigningJWK.KeyID()

	hdrs, err := buildSigningHeaders(kid)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := secrets.Sign(context.Background(), kid, []byte(`{}`), hdrs)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := parseJWSHeaders(signed)
	if err != nil {
		t.Fatal(err)
	}

	gotKID, ok := parsed.KeyID()
	if !ok || gotKID == "" {
		t.Fatal("expected non-empty kid")
	}
}

func TestParseJWSHeaders_InvalidJWS(t *testing.T) {
	_, err := parseJWSHeaders([]byte("not-a-jws"))
	if err == nil {
		t.Fatal("expected error for invalid JWS")
	}
}
