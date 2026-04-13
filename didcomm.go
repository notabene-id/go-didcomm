package didcomm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// UnpackResult contains the result of unpacking a DIDComm v2 message.
type UnpackResult struct {
	Message   *Message
	Encrypted bool
	Signed    bool
	Anonymous bool // true if anoncrypt (no skid), false if authcrypt
}

// Client provides DIDComm v2 pack and unpack operations.
type Client struct {
	resolver DIDResolver
	crypto   CryptoOperations
}

// NewClient creates a new DIDComm client.
func NewClient(resolver DIDResolver, crypto CryptoOperations) *Client {
	return &Client{resolver: resolver, crypto: crypto}
}

// PackSigned creates a JWS-signed DIDComm message.
// The message must have a From field to identify the signing key.
func (c *Client) PackSigned(ctx context.Context, msg *Message) ([]byte, error) {
	if err := msg.Validate(); err != nil {
		return nil, err
	}
	if msg.From == "" {
		return nil, ErrNoSender
	}

	kid, err := c.getSenderSigningKID(ctx, msg.From)
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal message: %w", err)
	}

	hdrs, err := buildSigningHeaders(kid)
	if err != nil {
		return nil, err
	}
	return c.crypto.Sign(ctx, kid, payload, hdrs)
}

// PackAnoncrypt creates an anonymous encrypted JWE DIDComm message.
// No sender identification is included.
func (c *Client) PackAnoncrypt(ctx context.Context, msg *Message) ([]byte, error) {
	if err := msg.Validate(); err != nil {
		return nil, err
	}
	if len(msg.To) == 0 {
		return nil, ErrNoRecipients
	}

	recipientKeys, err := c.getRecipientEncryptionKeys(ctx, msg.To)
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal message: %w", err)
	}

	return anoncrypt(payload, recipientKeys)
}

// PackAuthcrypt creates an authenticated encrypted DIDComm message (sign-then-encrypt).
// The message must have From and To fields.
func (c *Client) PackAuthcrypt(ctx context.Context, msg *Message) ([]byte, error) {
	if err := msg.Validate(); err != nil {
		return nil, err
	}
	if msg.From == "" {
		return nil, ErrNoSender
	}
	if len(msg.To) == 0 {
		return nil, ErrNoRecipients
	}

	kid, err := c.getSenderSigningKID(ctx, msg.From)
	if err != nil {
		return nil, err
	}

	recipientKeys, err := c.getRecipientEncryptionKeys(ctx, msg.To)
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal message: %w", err)
	}

	hdrs, err := buildSigningHeaders(kid)
	if err != nil {
		return nil, err
	}
	signed, err := c.crypto.Sign(ctx, kid, payload, hdrs)
	if err != nil {
		return nil, fmt.Errorf("authcrypt sign: %w", err)
	}

	return authcryptEnvelope(signed, kid, recipientKeys)
}

// Unpack auto-detects the format (JWE, JWS, or plain JSON) and unpacks accordingly.
func (c *Client) Unpack(ctx context.Context, envelope []byte) (*UnpackResult, error) {
	envelope = bytes.TrimSpace(envelope)

	if isJWE(envelope) {
		return c.unpackEncrypted(ctx, envelope)
	}
	if isJWS(envelope) {
		return c.unpackSigned(ctx, envelope)
	}
	return c.unpackPlain(envelope)
}

func (c *Client) unpackEncrypted(ctx context.Context, encrypted []byte) (*UnpackResult, error) {
	msg, err := jwe.Parse(encrypted)
	if err != nil {
		return nil, fmt.Errorf("parse JWE: %w", err)
	}

	decrypted, err := c.decryptJWE(ctx, encrypted, msg)
	if err != nil {
		return nil, err
	}

	hdrs := msg.ProtectedHeaders()
	var skid string
	if hdrs != nil {
		_ = hdrs.Get("skid", &skid)
	}

	result := &UnpackResult{
		Encrypted: true,
		Anonymous: skid == "",
	}

	if skid != "" {
		result.Signed = true
		payload, verifyErr := c.verifyAuthcryptSender(ctx, decrypted, skid)
		if verifyErr != nil {
			return nil, verifyErr
		}
		decrypted = payload
	}

	var m Message
	if err := json.Unmarshal(decrypted, &m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	result.Message = &m

	return result, nil
}

func (c *Client) decryptJWE(ctx context.Context, encrypted []byte, msg *jwe.Message) ([]byte, error) {
	for _, r := range msg.Recipients() {
		hdr := r.Headers()
		kid, ok := hdr.KeyID()
		if !ok {
			continue
		}

		decrypted, err := c.crypto.Decrypt(ctx, kid, encrypted)
		if err != nil {
			continue
		}
		return decrypted, nil
	}

	if hdrs := msg.ProtectedHeaders(); hdrs != nil {
		if kid, ok := hdrs.KeyID(); ok {
			if decrypted, err := c.crypto.Decrypt(ctx, kid, encrypted); err == nil {
				return decrypted, nil
			}
		}
	}

	return nil, fmt.Errorf("%w: no matching recipient key found", ErrDecryptionFailed)
}

func (c *Client) verifyAuthcryptSender(ctx context.Context, signed []byte, skid string) ([]byte, error) {
	senderPubKey, err := c.resolveKeyByKID(ctx, skid)
	if err != nil {
		return nil, fmt.Errorf("resolve sender key %s: %w", skid, err)
	}
	return verifySignature(signed, senderPubKey)
}

func (c *Client) unpackSigned(ctx context.Context, signed []byte) (*UnpackResult, error) {
	hdrs, err := parseJWSHeaders(signed)
	if err != nil {
		return nil, err
	}

	kid, ok := hdrs.KeyID()
	if !ok || kid == "" {
		return nil, fmt.Errorf("%w: JWS missing kid header", ErrVerificationFailed)
	}

	pubKey, err := c.resolveKeyByKID(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("resolve signing key %s: %w", kid, err)
	}

	payload, err := verifySignature(signed, pubKey)
	if err != nil {
		return nil, err
	}

	var m Message
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}

	return &UnpackResult{
		Message:   &m,
		Signed:    true,
		Encrypted: false,
		Anonymous: false,
	}, nil
}

func (c *Client) unpackPlain(data []byte) (*UnpackResult, error) {
	var m Message
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &UnpackResult{
		Message:   &m,
		Signed:    false,
		Encrypted: false,
		Anonymous: false,
	}, nil
}

// getSenderSigningKID resolves the sender's signing key ID from their DID document.
func (c *Client) getSenderSigningKID(ctx context.Context, did string) (string, error) {
	doc, err := c.resolver.Resolve(ctx, did)
	if err != nil {
		return "", err
	}

	vm, err := doc.FindSigningKey()
	if err != nil {
		return "", err
	}

	return vm.ID, nil
}

// getRecipientEncryptionKeys resolves public encryption keys for all recipients.
func (c *Client) getRecipientEncryptionKeys(ctx context.Context, dids []string) ([]jwk.Key, error) {
	var keys []jwk.Key
	for _, did := range dids {
		doc, err := c.resolver.Resolve(ctx, did)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", did, err)
		}

		vm, err := doc.FindEncryptionKey()
		if err != nil {
			return nil, fmt.Errorf("find encryption key for %s: %w", did, err)
		}

		keys = append(keys, vm.PublicKey)
	}
	return keys, nil
}

// resolveKeyByKID finds a public key by its key ID across all stored DID documents.
func (c *Client) resolveKeyByKID(ctx context.Context, kid string) (jwk.Key, error) {
	did := extractDIDFromKID(kid)
	if did == "" {
		return nil, fmt.Errorf("%w: cannot extract DID from kid %s", ErrKeyNotFound, kid)
	}

	doc, err := c.resolver.Resolve(ctx, did)
	if err != nil {
		return nil, err
	}

	for _, vm := range doc.Authentication {
		if vm.ID == kid {
			return vm.PublicKey, nil
		}
	}

	for _, vm := range doc.KeyAgreement {
		if vm.ID == kid {
			return vm.PublicKey, nil
		}
	}

	return nil, fmt.Errorf("%w: kid %s not found in DID document %s", ErrKeyNotFound, kid, did)
}

// extractDIDFromKID extracts the DID portion from a key ID (did:method:id#fragment -> did:method:id).
func extractDIDFromKID(kid string) string {
	for i := len(kid) - 1; i >= 0; i-- {
		if kid[i] == '#' {
			return kid[:i]
		}
	}
	return ""
}

// buildSigningHeaders creates the JWS protected headers for DIDComm signing.
func buildSigningHeaders(kid string) (jws.Headers, error) {
	hdrs := jws.NewHeaders()
	if kid != "" {
		if err := hdrs.Set(jws.KeyIDKey, kid); err != nil {
			return nil, fmt.Errorf("set kid header: %w", err)
		}
	}
	if err := hdrs.Set(jws.TypeKey, "application/didcomm-signed+json"); err != nil {
		return nil, fmt.Errorf("set typ header: %w", err)
	}
	return hdrs, nil
}

// isJWE checks if the data looks like a JWE (compact or JSON serialization).
func isJWE(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if data[0] == '{' {
		var peek struct {
			Recipients json.RawMessage `json:"recipients"`
			Ciphertext string          `json:"ciphertext"`
		}
		if err := json.Unmarshal(data, &peek); err == nil {
			return peek.Ciphertext != ""
		}
		return false
	}
	parts := bytes.Count(data, []byte("."))
	return parts == 4
}

// isJWS checks if the data looks like a JWS (compact serialization).
func isJWS(data []byte) bool {
	if len(data) == 0 || data[0] == '{' {
		return false
	}
	parts := bytes.Count(data, []byte("."))
	return parts == 2
}
