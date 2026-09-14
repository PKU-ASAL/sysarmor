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
	flags := flag.NewFlagSet("sysarmor-model-sign", flag.ContinueOnError)
	keyPath := flags.String("key", "", "Ed25519 private key PEM path")
	keyID := flags.String("key-id", "", "model signing key ID")
	inputPath := flags.String("input", "", "unsigned model bundle path")
	outputPath := flags.String("output", "", "signed model bundle path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *keyID == "" || *inputPath == "" || *outputPath == "" {
		return fmt.Errorf("--key, --key-id, --input, and --output are required")
	}
	return bootstrap.SignLearningModel(bootstrap.ModelSignOptions{
		KeyPath: *keyPath, KeyID: *keyID, InputPath: *inputPath, OutputPath: *outputPath,
	})
}
