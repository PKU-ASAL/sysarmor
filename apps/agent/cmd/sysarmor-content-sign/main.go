package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/bootstrap"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("sysarmor-content-sign", flag.ContinueOnError)
	keyPath := flags.String("key", "", "PKCS#8 Ed25519 private key")
	keyID := flags.String("key-id", "", "content signing key ID")
	inputPath := flags.String("input", "", "unsigned content JSON")
	outputPath := flags.String("output", "", "signed content JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *keyID == "" || *inputPath == "" || *outputPath == "" {
		return fmt.Errorf("--key, --key-id, --input, and --output are required")
	}
	return bootstrap.SignContent(bootstrap.ContentSignOptions{
		KeyPath: *keyPath, KeyID: *keyID, InputPath: *inputPath, OutputPath: *outputPath,
	})
}
