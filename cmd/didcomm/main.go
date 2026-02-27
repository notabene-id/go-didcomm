package main

import (
	"fmt"
	"os"
)

const version = "0.1.0"

const usage = `didcomm - DIDComm v2 messaging CLI

Usage:
  didcomm <command> [options]

Commands:
  did generate-key                                     Generate a did:key identity
  did generate-web --domain <d> [--path <p>]           Generate a did:web identity
  pack signed    --key-file <f> --did-doc <f> [--message <m>]   Sign a message (JWS)
  pack anoncrypt --did-doc <f> [--message <m>]                  Anonymous encrypt (JWE)
  pack authcrypt --key-file <f> --did-doc <f> [--message <m>]   Sign-then-encrypt
  unpack         --key-file <f> [--did-doc <f>] [--message <m>] Unpack a message
  send           --to <url> [--message <m>]                     HTTP POST to endpoint
  version                                              Print version
  help                                                 Print this help

Message input (--message flag):
  -           Read from stdin (default)
  @file.json  Read from file
  '{"json"}'  Inline JSON string

Examples:
  # Generate a did:key identity
  didcomm did generate-key --output-dir alice

  # Pack a signed message
  echo '{"id":"1","type":"example","from":"did:key:z...","body":{}}' | \
    didcomm pack signed --key-file alice/keys.json --did-doc alice/did-doc.json

  # Unpack a message
  didcomm unpack --key-file bob/keys.json --did-doc alice/did-doc.json,bob/did-doc.json --message @packed.json
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "did":
		err = runDID(os.Args[2:])
	case "pack":
		err = runPack(os.Args[2:])
	case "unpack":
		err = runUnpack(os.Args[2:])
	case "send":
		err = runSend(os.Args[2:])
	case "version":
		fmt.Println("didcomm " + version)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprintln(os.Stderr, "unknown command: "+os.Args[1]+"\n") //nolint:gosec // CLI stderr output, no XSS risk
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
