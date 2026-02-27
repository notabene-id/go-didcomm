package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"

	didcomm "github.com/Notabene-id/go-didcomm"
)

// readMessageInput reads message data based on the flag value:
//   - "-" or empty: read from stdin
//   - "@filename": read from file
//   - otherwise: treat as inline JSON string
func readMessageInput(flag string) ([]byte, error) {
	if flag == "" || flag == "-" {
		return io.ReadAll(os.Stdin)
	}
	if strings.HasPrefix(flag, "@") {
		return os.ReadFile(flag[1:])
	}
	return []byte(flag), nil
}

// verificationMethodJSON is a serializable form of VerificationMethod with publicKeyJwk.
type verificationMethodJSON struct {
	ID           string          `json:"id"`
	Type         string          `json:"type"`
	Controller   string          `json:"controller"`
	PublicKeyJWK json.RawMessage `json:"publicKeyJwk"`
}

// didDocJSON is a serializable form of DIDDocument with embedded public keys.
type didDocJSON struct {
	ID             string                   `json:"id"`
	Authentication []verificationMethodJSON `json:"authentication"`
	KeyAgreement   []verificationMethodJSON `json:"keyAgreement"`
	Service        []didcomm.Service        `json:"service,omitempty"`
}

// marshalDIDDoc serializes a DIDDocument to JSON including public keys as publicKeyJwk.
func marshalDIDDoc(doc *didcomm.DIDDocument) ([]byte, error) {
	out := didDocJSON{
		ID:      doc.ID,
		Service: doc.Service,
	}

	for _, vm := range doc.Authentication {
		jwkBytes, err := json.Marshal(vm.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("marshal authentication key %s: %w", vm.ID, err)
		}
		out.Authentication = append(out.Authentication, verificationMethodJSON{
			ID:           vm.ID,
			Type:         vm.Type,
			Controller:   vm.Controller,
			PublicKeyJWK: jwkBytes,
		})
	}

	for _, vm := range doc.KeyAgreement {
		jwkBytes, err := json.Marshal(vm.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("marshal key agreement key %s: %w", vm.ID, err)
		}
		out.KeyAgreement = append(out.KeyAgreement, verificationMethodJSON{
			ID:           vm.ID,
			Type:         vm.Type,
			Controller:   vm.Controller,
			PublicKeyJWK: jwkBytes,
		})
	}

	return json.MarshalIndent(out, "", "  ")
}

// unmarshalDIDDoc deserializes a DIDDocument from JSON, restoring publicKeyJwk into PublicKey.
func unmarshalDIDDoc(data []byte) (*didcomm.DIDDocument, error) {
	var raw didDocJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse DID document: %w", err)
	}

	doc := &didcomm.DIDDocument{
		ID:      raw.ID,
		Service: raw.Service,
	}

	for _, vm := range raw.Authentication {
		key, err := jwk.ParseKey(vm.PublicKeyJWK)
		if err != nil {
			return nil, fmt.Errorf("parse authentication key %s: %w", vm.ID, err)
		}
		doc.Authentication = append(doc.Authentication, didcomm.VerificationMethod{
			ID:         vm.ID,
			Type:       vm.Type,
			Controller: vm.Controller,
			PublicKey:  key,
		})
	}

	for _, vm := range raw.KeyAgreement {
		key, err := jwk.ParseKey(vm.PublicKeyJWK)
		if err != nil {
			return nil, fmt.Errorf("parse key agreement key %s: %w", vm.ID, err)
		}
		doc.KeyAgreement = append(doc.KeyAgreement, didcomm.VerificationMethod{
			ID:         vm.ID,
			Type:       vm.Type,
			Controller: vm.Controller,
			PublicKey:  key,
		})
	}

	return doc, nil
}

// marshalKeyPair serializes a KeyPair's private keys as a JWK Set.
func marshalKeyPair(kp *didcomm.KeyPair) ([]byte, error) {
	set := jwk.NewSet()
	if err := set.AddKey(kp.SigningJWK); err != nil {
		return nil, fmt.Errorf("add signing key to set: %w", err)
	}
	if err := set.AddKey(kp.EncryptionJWK); err != nil {
		return nil, fmt.Errorf("add encryption key to set: %w", err)
	}
	return json.MarshalIndent(set, "", "  ")
}

// loadKeyFile loads a JWK Set from a file and stores all keys in an InMemorySecretsStore.
func loadKeyFile(path string) (*didcomm.InMemorySecretsStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file %s: %w", path, err)
	}

	set, err := jwk.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse key file %s: %w", path, err)
	}

	store := didcomm.NewInMemorySecretsStore()
	for i := range set.Len() {
		key, ok := set.Key(i)
		if !ok {
			continue
		}
		store.StoreKey(key)
	}
	return store, nil
}

// loadDIDDocs loads DID documents from a comma-separated list of file paths.
func loadDIDDocs(paths string) (*didcomm.Resolver, error) {
	resolver := didcomm.NewResolver()
	if paths == "" {
		return resolver, nil
	}

	for _, p := range strings.Split(paths, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read DID document %s: %w", p, err)
		}
		doc, err := unmarshalDIDDoc(data)
		if err != nil {
			return nil, fmt.Errorf("parse DID document %s: %w", p, err)
		}
		resolver.Store(doc)
	}
	return resolver, nil
}

// buildClient creates a Client from a key file path and comma-separated DID doc paths.
func buildClient(keyFile, didDocPaths string) (*didcomm.Client, error) {
	secrets, err := loadKeyFile(keyFile)
	if err != nil {
		return nil, err
	}

	resolver, err := loadDIDDocs(didDocPaths)
	if err != nil {
		return nil, err
	}

	return didcomm.NewClient(resolver, secrets), nil
}

const (
	contentTypeEncrypted = "application/didcomm-encrypted+json"
	contentTypeSigned    = "application/didcomm-signed+json"
	contentTypePlain     = "application/didcomm-plain+json"
)

// detectContentType returns the DIDComm media type based on the envelope format.
func detectContentType(data []byte) string {
	data = []byte(strings.TrimSpace(string(data)))
	dots := strings.Count(string(data), ".")

	switch dots {
	case 4:
		return contentTypeEncrypted
	case 2:
		return contentTypeSigned
	default:
		// JSON serialization JWE or plain
		if len(data) > 0 && data[0] == '{' {
			var peek struct {
				Ciphertext string `json:"ciphertext"`
			}
			if err := json.Unmarshal(data, &peek); err == nil && peek.Ciphertext != "" {
				return contentTypeEncrypted
			}
		}
		return contentTypePlain
	}
}

// parseMessage parses raw JSON bytes into a didcomm.Message.
func parseMessage(data []byte) (*didcomm.Message, error) {
	var msg didcomm.Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("parse message JSON: %w", err)
	}
	return &msg, nil
}

// httpClient is the HTTP client used for sending messages, replaceable for testing.
var httpClient interface {
	Do(req *http.Request) (*http.Response, error)
} = http.DefaultClient
