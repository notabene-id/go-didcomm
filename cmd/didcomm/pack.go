package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	didcomm "github.com/Notabene-id/go-didcomm"
)

func runPack(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: didcomm pack <signed|anoncrypt|authcrypt> [options]")
	}

	switch args[0] {
	case "signed":
		return runPackSigned(args[1:])
	case "anoncrypt":
		return runPackAnoncrypt(args[1:])
	case "authcrypt":
		return runPackAuthcrypt(args[1:])
	default:
		return fmt.Errorf("unknown pack subcommand: %s", args[0])
	}
}

func runPackSigned(args []string) error {
	fs := flag.NewFlagSet("pack signed", flag.ContinueOnError)
	keyFile := fs.String("key-file", "", "path to JWK Set file with private keys (required)")
	didDoc := fs.String("did-doc", "", "comma-separated DID document file paths (optional, for overrides)")
	message := fs.String("message", "-", "message input: - (stdin), @file, or inline JSON")
	send := fs.Bool("send", false, "resolve recipient endpoint and send packed message")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *keyFile == "" {
		return fmt.Errorf("--key-file is required")
	}

	client, err := buildClient(*keyFile, *didDoc)
	if err != nil {
		return err
	}

	data, err := readMessageInput(*message)
	if err != nil {
		return fmt.Errorf("read message: %w", err)
	}

	msg, err := parseMessage(data)
	if err != nil {
		return err
	}

	packed, err := client.PackSigned(context.Background(), msg)
	if err != nil {
		return fmt.Errorf("pack signed: %w", err)
	}

	if *send {
		return sendToRecipient(packed, msg.To, *didDoc)
	}

	_, err = os.Stdout.Write(packed)
	return err
}

func runPackAnoncrypt(args []string) error {
	fs := flag.NewFlagSet("pack anoncrypt", flag.ContinueOnError)
	didDoc := fs.String("did-doc", "", "comma-separated DID document file paths (optional, for overrides)")
	message := fs.String("message", "-", "message input: - (stdin), @file, or inline JSON")
	send := fs.Bool("send", false, "resolve recipient endpoint and send packed message")
	if err := fs.Parse(args); err != nil {
		return err
	}

	resolver, err := buildResolverWithOverrides(*didDoc)
	if err != nil {
		return err
	}

	secrets := didcomm.NewInMemorySecretsStore()
	client := didcomm.NewClient(resolver, secrets)

	data, err := readMessageInput(*message)
	if err != nil {
		return fmt.Errorf("read message: %w", err)
	}

	msg, err := parseMessage(data)
	if err != nil {
		return err
	}

	packed, err := client.PackAnoncrypt(context.Background(), msg)
	if err != nil {
		return fmt.Errorf("pack anoncrypt: %w", err)
	}

	if *send {
		return sendToRecipient(packed, msg.To, *didDoc)
	}

	_, err = os.Stdout.Write(packed)
	return err
}

func runPackAuthcrypt(args []string) error {
	fs := flag.NewFlagSet("pack authcrypt", flag.ContinueOnError)
	keyFile := fs.String("key-file", "", "path to JWK Set file with private keys (required)")
	didDoc := fs.String("did-doc", "", "comma-separated DID document file paths (optional, for overrides)")
	message := fs.String("message", "-", "message input: - (stdin), @file, or inline JSON")
	send := fs.Bool("send", false, "resolve recipient endpoint and send packed message")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *keyFile == "" {
		return fmt.Errorf("--key-file is required")
	}

	client, err := buildClient(*keyFile, *didDoc)
	if err != nil {
		return err
	}

	data, err := readMessageInput(*message)
	if err != nil {
		return fmt.Errorf("read message: %w", err)
	}

	msg, err := parseMessage(data)
	if err != nil {
		return err
	}

	packed, err := client.PackAuthcrypt(context.Background(), msg)
	if err != nil {
		return fmt.Errorf("pack authcrypt: %w", err)
	}

	if *send {
		return sendToRecipient(packed, msg.To, *didDoc)
	}

	_, err = os.Stdout.Write(packed)
	return err
}

// sendToRecipient resolves the first recipient's DID document, finds its DIDCommMessaging
// service endpoint, and POSTs the packed message to it.
func sendToRecipient(packed []byte, recipients []string, didDocPaths string) error {
	if len(recipients) == 0 {
		return fmt.Errorf("no recipients in message — cannot determine endpoint")
	}

	resolver, err := buildResolverWithOverrides(didDocPaths)
	if err != nil {
		return err
	}

	ctx := context.Background()
	doc, err := resolver.Resolve(ctx, recipients[0])
	if err != nil {
		return fmt.Errorf("resolve recipient %s: %w", recipients[0], err)
	}

	endpoint, err := doc.FindDIDCommEndpoint()
	if err != nil {
		return fmt.Errorf("recipient %s has no service endpoint — use 'didcomm send --to <url>' to send manually", recipients[0])
	}

	contentType := detectContentType(packed)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(packed))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send to %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	fmt.Fprintln(os.Stderr, "HTTP "+resp.Status) //nolint:gosec // CLI stderr output
	if len(body) > 0 {
		_, _ = os.Stdout.Write(body)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned %s", resp.Status)
	}
	return nil
}
