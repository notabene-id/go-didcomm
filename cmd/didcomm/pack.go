package main

import (
	"context"
	"flag"
	"fmt"
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
	didDoc := fs.String("did-doc", "", "comma-separated DID document file paths (required)")
	message := fs.String("message", "-", "message input: - (stdin), @file, or inline JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *keyFile == "" {
		return fmt.Errorf("--key-file is required")
	}
	if *didDoc == "" {
		return fmt.Errorf("--did-doc is required")
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

	_, err = os.Stdout.Write(packed)
	return err
}

func runPackAnoncrypt(args []string) error {
	fs := flag.NewFlagSet("pack anoncrypt", flag.ContinueOnError)
	didDoc := fs.String("did-doc", "", "comma-separated DID document file paths (required)")
	message := fs.String("message", "-", "message input: - (stdin), @file, or inline JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *didDoc == "" {
		return fmt.Errorf("--did-doc is required")
	}

	resolver, err := loadDIDDocs(*didDoc)
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

	_, err = os.Stdout.Write(packed)
	return err
}

func runPackAuthcrypt(args []string) error {
	fs := flag.NewFlagSet("pack authcrypt", flag.ContinueOnError)
	keyFile := fs.String("key-file", "", "path to JWK Set file with private keys (required)")
	didDoc := fs.String("did-doc", "", "comma-separated DID document file paths (required)")
	message := fs.String("message", "-", "message input: - (stdin), @file, or inline JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *keyFile == "" {
		return fmt.Errorf("--key-file is required")
	}
	if *didDoc == "" {
		return fmt.Errorf("--did-doc is required")
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

	_, err = os.Stdout.Write(packed)
	return err
}
