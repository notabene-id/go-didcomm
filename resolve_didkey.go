package didcomm

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/mr-tron/base58"

	"github.com/Notabene-id/go-didcomm/internal/convert"
)

// DIDKeyResolver resolves did:key DIDs locally by decoding the multicodec-encoded public key.
type DIDKeyResolver struct{}

// Resolve parses a did:key DID and returns a DIDDocument with authentication and key agreement keys.
func (r *DIDKeyResolver) Resolve(_ context.Context, did string) (*DIDDocument, error) {
	if len(did) < len("did:key:z") || did[:8] != "did:key:" {
		return nil, fmt.Errorf("%w: not a did:key DID: %s", ErrDIDNotFound, did)
	}

	fragment := did[8:] // everything after "did:key:"
	if fragment[0] != 'z' {
		return nil, fmt.Errorf("%w: did:key missing multibase 'z' prefix: %s", ErrDIDNotFound, did)
	}

	decoded, err := base58.Decode(fragment[1:])
	if err != nil {
		return nil, fmt.Errorf("%w: decode base58: %w", ErrDIDNotFound, err)
	}

	codec, n := binary.Uvarint(decoded)
	if n <= 0 {
		return nil, fmt.Errorf("%w: invalid multicodec varint in %s", ErrDIDNotFound, did)
	}

	pubKeyBytes := decoded[n:]

	switch codec {
	case multicodecEd25519:
		return buildDIDKeyDoc(did, fragment, pubKeyBytes)
	default:
		return nil, fmt.Errorf("%w: unsupported multicodec 0x%x in %s", ErrUnsupportedKeyType, codec, did)
	}
}

// buildDIDKeyDoc constructs a DIDDocument from an Ed25519 public key embedded in a did:key.
func buildDIDKeyDoc(did, sigFragment string, ed25519PubBytes []byte) (*DIDDocument, error) {
	if len(ed25519PubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid Ed25519 key length %d", ErrDIDNotFound, len(ed25519PubBytes))
	}

	sigKID := did + "#" + sigFragment

	// Derive X25519 public key
	x25519PubBytes, err := convert.Ed25519PublicToX25519(ed25519PubBytes)
	if err != nil {
		return nil, fmt.Errorf("convert ed25519 to x25519: %w", err)
	}

	encFragment := encodeDIDKeyFragment(multicodecX25519, x25519PubBytes)
	encKID := did + "#" + encFragment

	// Build signing public JWK
	sigPubJWK, err := jwk.Import(ed25519.PublicKey(ed25519PubBytes))
	if err != nil {
		return nil, fmt.Errorf("import ed25519 public key: %w", err)
	}
	_ = sigPubJWK.Set(jwk.KeyIDKey, sigKID)
	_ = sigPubJWK.Set(jwk.AlgorithmKey, jwa.EdDSA())

	// Convert to ecdh.PublicKey so jwk.Import produces the correct key type for JWE
	x25519Pub, err := ecdh.X25519().NewPublicKey(x25519PubBytes)
	if err != nil {
		return nil, fmt.Errorf("create x25519 public key: %w", err)
	}

	// Build encryption public JWK
	encPubJWK, err := jwk.Import(x25519Pub)
	if err != nil {
		return nil, fmt.Errorf("import x25519 public key: %w", err)
	}
	_ = encPubJWK.Set(jwk.KeyIDKey, encKID)
	_ = encPubJWK.Set(jwk.AlgorithmKey, jwa.ECDH_ES_A256KW())
	_ = encPubJWK.Set(jwk.KeyOpsKey, jwk.KeyOperationList{jwk.KeyOpDeriveKey})

	return &DIDDocument{
		ID: did,
		Authentication: []VerificationMethod{
			{
				ID:         sigKID,
				Type:       "Ed25519VerificationKey2020",
				Controller: did,
				PublicKey:  sigPubJWK,
			},
		},
		KeyAgreement: []VerificationMethod{
			{
				ID:         encKID,
				Type:       "X25519KeyAgreementKey2020",
				Controller: did,
				PublicKey:  encPubJWK,
			},
		},
	}, nil
}
