package didcomm

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// anoncrypt encrypts a payload for one or more recipients using ECDH-ES+A256KW / A256CBC-HS512.
// This is anonymous encryption — the sender is not identified.
func anoncrypt(payload []byte, recipientKeys []jwk.Key) ([]byte, error) {
	if len(recipientKeys) == 0 {
		return nil, ErrNoRecipients
	}

	opts := []jwe.EncryptOption{
		jwe.WithContentEncryption(jwa.A256CBC_HS512()),
	}

	for _, rk := range recipientKeys {
		per := jwe.NewHeaders()
		if kid, ok := rk.KeyID(); ok && kid != "" {
			if err := mustSet(per, jwe.KeyIDKey, kid); err != nil {
				return nil, err
			}
		}
		opts = append(opts, jwe.WithKey(jwa.ECDH_ES_A256KW(), rk, jwe.WithPerRecipientHeaders(per)))
	}

	hdrs := jwe.NewHeaders()
	if err := mustSet(hdrs, jwe.TypeKey, "application/didcomm-encrypted+json"); err != nil {
		return nil, err
	}

	// NOTE: DIDComm v2 recommends APV (Agreement PartyVInfo) in the protected headers.
	// However, jwx v3 has a bug where X25519 encryption ignores apu/apv in the Concat KDF
	// while decryption uses them, causing a mismatch. APV is omitted until this is fixed.

	opts = append(opts, jwe.WithProtectedHeaders(hdrs))
	opts = append(opts, jwe.WithJSON())

	encrypted, err := jwe.Encrypt(payload, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEncryptionFailed, err)
	}
	return encrypted, nil
}
