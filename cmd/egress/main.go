// Command egress runs the outbound trust boundary as one process on one host.
//
// It takes its whole configuration from that host — flags, then the environment
// — and its KMS identity from a mnemonic the host holds. There is no
// orchestrator to ask, which is the point: this process runs where a cloud API
// token does not reach.
package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/hanzoai/egress"
)

func main() {
	var cfg egress.Config
	cfg.Flags(flag.CommandLine)
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	store, close, err := egress.Vault(cfg)
	if err != nil {
		log.Error("cannot open the credential store", "error", err.Error())
		os.Exit(1)
	}
	defer close()

	server, err := egress.New(cfg, store, log)
	if err != nil {
		log.Error("cannot serve", "error", err.Error())
		os.Exit(1)
	}
	log.Info("serving", "listen", cfg.Listen, "issuer", cfg.Issuer, "kms", cfg.KMS)
	if err := server.Listen(); err != nil {
		log.Error("stopped", "error", err.Error())
		os.Exit(1)
	}
}
