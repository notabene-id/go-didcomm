package didcomm

import (
	"context"
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// CryptoOperations provides sealed signing and decryption operations.
// Implementations hold private key material internally — callers receive
// only the results of cryptographic operations, never raw keys.
type CryptoOperations interface {
	// Sign signs payload using the EdDSA key identified by kid.
	// The provided headers are set as JWS protected headers.
	Sign(ctx context.Context, kid string, payload []byte, headers jws.Headers) ([]byte, error)

	// Decrypt decrypts a JWE message using the ECDH-ES+A256KW key identified by kid.
	Decrypt(ctx context.Context, kid string, encrypted []byte) ([]byte, error)
}

// InMemorySecretsStore is an in-memory implementation of CryptoOperations.
// Private keys are held in memory and never exposed via a getter.
type InMemorySecretsStore struct {
	mu   sync.RWMutex
	keys map[string]jwk.Key
}

// NewInMemorySecretsStore creates a new empty in-memory secrets store.
func NewInMemorySecretsStore() *InMemorySecretsStore {
	return &InMemorySecretsStore{
		keys: make(map[string]jwk.Key),
	}
}

// Store adds a key pair's private keys to the store, indexed by their key IDs.
func (s *InMemorySecretsStore) Store(kp *KeyPair) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if kid, ok := kp.SigningJWK.KeyID(); ok && kid != "" {
		s.keys[kid] = kp.SigningJWK
	}
	if kid, ok := kp.EncryptionJWK.KeyID(); ok && kid != "" {
		s.keys[kid] = kp.EncryptionJWK
	}
}

// StoreKey adds a single JWK to the store indexed by its key ID.
func (s *InMemorySecretsStore) StoreKey(key jwk.Key) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if kid, ok := key.KeyID(); ok && kid != "" {
		s.keys[kid] = key
	}
}

func (s *InMemorySecretsStore) getKey(kid string) (jwk.Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, ok := s.keys[kid]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return key, nil
}

// Sign signs payload using the key identified by kid.
func (s *InMemorySecretsStore) Sign(_ context.Context, kid string, payload []byte, headers jws.Headers) ([]byte, error) {
	key, err := s.getKey(kid)
	if err != nil {
		return nil, err
	}
	signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSA(), key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSigningFailed, err)
	}
	return signed, nil
}

// Decrypt decrypts a JWE message using the key identified by kid.
func (s *InMemorySecretsStore) Decrypt(_ context.Context, kid string, encrypted []byte) ([]byte, error) {
	key, err := s.getKey(kid)
	if err != nil {
		return nil, err
	}
	decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.ECDH_ES_A256KW(), key))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}
	return decrypted, nil
}
