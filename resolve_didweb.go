package didcomm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// DIDWebResolver resolves did:web DIDs by fetching DID documents over HTTPS.
type DIDWebResolver struct {
	// HTTPClient is the HTTP client used for fetching DID documents.
	// If nil, http.DefaultClient is used.
	HTTPClient *http.Client
}

// Resolve fetches and parses a did:web DID document.
func (r *DIDWebResolver) Resolve(ctx context.Context, did string) (*DIDDocument, error) {
	if !strings.HasPrefix(did, "did:web:") {
		return nil, fmt.Errorf("%w: not a did:web DID: %s", ErrDIDNotFound, did)
	}

	url, err := didWebToURL(did)
	if err != nil {
		return nil, err
	}

	client := r.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create request for %s: %w", did, err)
	}
	req.Header.Set("Accept", "application/did+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch DID document for %s: %w", did, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d fetching %s", ErrDIDNotFound, resp.StatusCode, did)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read DID document for %s: %w", did, err)
	}

	var doc DIDDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse DID document for %s: %w", did, err)
	}

	if doc.ID != did {
		return nil, fmt.Errorf("%w: document id %q does not match requested %q", ErrDIDNotFound, doc.ID, did)
	}

	return &doc, nil
}

// didWebToURL converts a did:web identifier to its HTTPS URL.
//
// Examples:
//
//	did:web:example.com              → https://example.com/.well-known/did.json
//	did:web:example.com:users:alice  → https://example.com/users/alice/did.json
//	did:web:localhost%3A8080         → https://localhost:8080/.well-known/did.json
func didWebToURL(did string) (string, error) {
	if !strings.HasPrefix(did, "did:web:") {
		return "", fmt.Errorf("not a did:web DID: %s", did)
	}

	specific := did[len("did:web:"):]
	if specific == "" {
		return "", fmt.Errorf("empty did:web identifier")
	}

	// Split on ":" to get path components
	parts := strings.Split(specific, ":")

	// First part is the domain (with %3A decoded to ":")
	domain := strings.ReplaceAll(parts[0], "%3A", ":")

	if len(parts) == 1 {
		// No path — use .well-known
		return "https://" + domain + "/.well-known/did.json", nil
	}

	// Remaining parts form the path
	path := strings.Join(parts[1:], "/")
	return "https://" + domain + "/" + path + "/did.json", nil
}
