package didcomm

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// verifySignature verifies a JWS (compact or JSON serialization) and returns the payload.
func verifySignature(signed []byte, publicKey jwk.Key) ([]byte, error) {
	payload, err := jws.Verify(
		signed,
		jws.WithKey(jwa.EdDSA(), publicKey),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrVerificationFailed, err)
	}
	return payload, nil
}

// parseJWSHeaders extracts the protected headers from a JWS message without verifying.
func parseJWSHeaders(signed []byte) (jws.Headers, error) {
	msg, err := jws.Parse(signed)
	if err != nil {
		return nil, fmt.Errorf("parse JWS: %w", err)
	}

	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return nil, fmt.Errorf("no signatures in JWS")
	}

	return sigs[0].ProtectedHeaders(), nil
}
