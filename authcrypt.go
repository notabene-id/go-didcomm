package didcomm

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// authcryptEnvelope encrypts an already-signed JWS payload for the recipients,
// including sender identification via the skid protected header.
func authcryptEnvelope(signed []byte, senderKID string, recipientKeys []jwk.Key) ([]byte, error) {
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
	if senderKID != "" {
		if err := mustSet(hdrs, "skid", senderKID); err != nil {
			return nil, err
		}
	}
	opts = append(opts, jwe.WithProtectedHeaders(hdrs), jwe.WithJSON())

	encrypted, err := jwe.Encrypt(signed, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEncryptionFailed, err)
	}
	return encrypted, nil
}
