package didcomm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDidWebToURL(t *testing.T) {
	tests := []struct {
		did     string
		wantURL string
	}{
		{"did:web:example.com", "https://example.com/.well-known/did.json"},
		{"did:web:example.com:users:alice", "https://example.com/users/alice/did.json"},
		{"did:web:localhost%3A8080", "https://localhost:8080/.well-known/did.json"},
		{"did:web:localhost%3A8080:api:v1", "https://localhost:8080/api/v1/did.json"},
		{"did:web:example.com:a:b:c", "https://example.com/a/b/c/did.json"},
	}

	for _, tt := range tests {
		t.Run(tt.did, func(t *testing.T) {
			got, err := didWebToURL(tt.did)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.wantURL {
				t.Fatalf("got %s, want %s", got, tt.wantURL)
			}
		})
	}
}

func TestDidWebToURL_Invalid(t *testing.T) {
	tests := []string{
		"did:key:z123",
		"did:web:",
		"not-a-did",
	}
	for _, did := range tests {
		t.Run(did, func(t *testing.T) {
			_, err := didWebToURL(did)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestDIDWebResolver_Resolve(t *testing.T) {
	doc, _, err := GenerateDIDWeb("localhost", "")
	if err != nil {
		t.Fatal(err)
	}

	docBytes, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/did.json" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/did+json")
		w.Write(docBytes)
	}))
	defer server.Close()

	// Extract host from test server URL (e.g. "127.0.0.1:PORT")
	host := server.Listener.Addr().String()

	// Override the doc ID to match what did:web would produce from the test server
	testDID := "did:web:" + encodeWebHost(host)
	doc.ID = testDID
	// Re-marshal with corrected ID
	docBytes, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	resolver := &DIDWebResolver{HTTPClient: server.Client()}

	// We need to intercept the URL resolution — use a custom transport
	origTransport := server.Client().Transport
	server.Client().Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		// Rewrite the request URL to point to our test server
		req.URL.Scheme = "https"
		req.URL.Host = host
		return origTransport.RoundTrip(req)
	})

	resolved, err := resolver.Resolve(context.Background(), testDID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if resolved.ID != testDID {
		t.Fatalf("ID mismatch: %s != %s", resolved.ID, testDID)
	}
	if len(resolved.Authentication) != 1 {
		t.Fatalf("expected 1 auth method, got %d", len(resolved.Authentication))
	}
}

func TestDIDWebResolver_Resolve_WithPath(t *testing.T) {
	doc, _, err := GenerateDIDWeb("localhost", "/users/alice")
	if err != nil {
		t.Fatal(err)
	}

	host := "" // set after server starts
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/alice/did.json" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/did+json")
		// Use current doc (ID updated after server starts)
		docBytes, marshalErr := json.Marshal(doc)
		if marshalErr != nil {
			t.Errorf("marshal doc: %v", marshalErr)
			return
		}
		w.Write(docBytes)
	}))
	defer server.Close()

	host = server.Listener.Addr().String()
	testDID := "did:web:" + encodeWebHost(host) + ":users:alice"
	doc.ID = testDID

	resolver := &DIDWebResolver{HTTPClient: server.Client()}
	origTransport := server.Client().Transport
	server.Client().Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		req.URL.Scheme = "https"
		req.URL.Host = host
		return origTransport.RoundTrip(req)
	})

	resolved, err := resolver.Resolve(context.Background(), testDID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if resolved.ID != testDID {
		t.Fatalf("ID mismatch: %s != %s", resolved.ID, testDID)
	}
}

func TestDIDWebResolver_NotFound(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	host := server.Listener.Addr().String()
	testDID := "did:web:" + encodeWebHost(host)

	resolver := &DIDWebResolver{HTTPClient: server.Client()}
	origTransport := server.Client().Transport
	server.Client().Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		req.URL.Scheme = "https"
		req.URL.Host = host
		return origTransport.RoundTrip(req)
	})

	_, err := resolver.Resolve(context.Background(), testDID)
	if !errors.Is(err, ErrDIDNotFound) {
		t.Fatalf("expected ErrDIDNotFound, got %v", err)
	}
}

func TestDIDWebResolver_IDMismatch(t *testing.T) {
	doc, _, err := GenerateDIDWeb("example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	// doc.ID is "did:web:example.com" but we'll request a different DID

	docBytes, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(docBytes)
	}))
	defer server.Close()

	host := server.Listener.Addr().String()
	testDID := "did:web:" + encodeWebHost(host)

	resolver := &DIDWebResolver{HTTPClient: server.Client()}
	origTransport := server.Client().Transport
	server.Client().Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		req.URL.Scheme = "https"
		req.URL.Host = host
		return origTransport.RoundTrip(req)
	})

	_, err = resolver.Resolve(context.Background(), testDID)
	if !errors.Is(err, ErrDIDNotFound) {
		t.Fatalf("expected ErrDIDNotFound for ID mismatch, got %v", err)
	}
}

func TestDIDWebResolver_NotDIDWeb(t *testing.T) {
	resolver := &DIDWebResolver{}
	_, err := resolver.Resolve(context.Background(), "did:key:z123")
	if !errors.Is(err, ErrDIDNotFound) {
		t.Fatalf("expected ErrDIDNotFound, got %v", err)
	}
}

// encodeWebHost encodes a host:port as a did:web domain (replacing ":" with "%3A").
func encodeWebHost(host string) string {
	return strings.ReplaceAll(host, ":", "%3A")
}

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
