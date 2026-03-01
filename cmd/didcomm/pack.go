package main

import "github.com/Notabene-id/go-didcomm/cli"

func runPack(args []string) error {
	return cli.RunPack(args)
}

func sendToRecipient(packed []byte, recipients []string, didDocPaths string) error {
	return cli.SendToRecipient(packed, recipients, didDocPaths)
}
