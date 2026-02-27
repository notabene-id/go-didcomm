package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	didcomm "github.com/Notabene-id/go-didcomm"
)

func runDID(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: didcomm did <generate-key|generate-web> [options]")
	}

	switch args[0] {
	case "generate-key":
		return runDIDGenerateKey(args[1:])
	case "generate-web":
		return runDIDGenerateWeb(args[1:])
	default:
		return fmt.Errorf("unknown did subcommand: %s", args[0])
	}
}

// generateOutput is the combined output format for generate commands.
type generateOutput struct {
	DIDDocument json.RawMessage `json:"didDocument"`
	Keys        json.RawMessage `json:"keys"`
}

func writeGenerateOutput(doc *didcomm.DIDDocument, kp *didcomm.KeyPair, outputDir string) error {
	docBytes, err := marshalDIDDoc(doc)
	if err != nil {
		return fmt.Errorf("marshal DID document: %w", err)
	}

	keyBytes, err := marshalKeyPair(kp)
	if err != nil {
		return fmt.Errorf("marshal keys: %w", err)
	}

	if outputDir != "" {
		return writeOutputDir(outputDir, docBytes, keyBytes)
	}

	out := generateOutput{
		DIDDocument: docBytes,
		Keys:        keyBytes,
	}
	result, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal output: %w", err)
	}
	fmt.Println(string(result))
	return nil
}

func writeOutputDir(outputDir string, docBytes, keyBytes []byte) error {
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "did-doc.json"), docBytes, 0o600); err != nil {
		return fmt.Errorf("write DID document: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "keys.json"), keyBytes, 0o600); err != nil {
		return fmt.Errorf("write keys: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Wrote %s/did-doc.json and %s/keys.json\n", outputDir, outputDir)
	return nil
}

func runDIDGenerateKey(args []string) error {
	fs := flag.NewFlagSet("did generate-key", flag.ContinueOnError)
	outputDir := fs.String("output-dir", "", "write did-doc.json and keys.json to this directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	doc, kp, err := didcomm.GenerateDIDKey()
	if err != nil {
		return fmt.Errorf("generate did:key: %w", err)
	}

	return writeGenerateOutput(doc, kp, *outputDir)
}

func runDIDGenerateWeb(args []string) error {
	fs := flag.NewFlagSet("did generate-web", flag.ContinueOnError)
	domain := fs.String("domain", "", "domain for did:web (required)")
	path := fs.String("path", "", "optional path for did:web")
	serviceEndpoint := fs.String("service-endpoint", "", "optional DIDCommMessaging service endpoint URL")
	outputDir := fs.String("output-dir", "", "write did-doc.json and keys.json to this directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *domain == "" {
		return fmt.Errorf("--domain is required")
	}

	doc, kp, err := didcomm.GenerateDIDWeb(*domain, *path)
	if err != nil {
		return fmt.Errorf("generate did:web: %w", err)
	}

	if *serviceEndpoint != "" {
		doc.Service = append(doc.Service, didcomm.Service{
			ID:              doc.ID + "#didcomm",
			Type:            "DIDCommMessaging",
			ServiceEndpoint: *serviceEndpoint,
		})
	}

	return writeGenerateOutput(doc, kp, *outputDir)
}
