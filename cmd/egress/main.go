// Command egress runs the outbound trust boundary as one process on one host.
//
// It takes its whole configuration from that host — flags, then the environment
// — and its KMS identity from a mnemonic the host holds. There is no
// orchestrator to ask, which is the point: this process runs where a cloud API
// token does not reach.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/hanzoai/egress"
	kms "github.com/luxfi/kms/pkg/store"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "mint" {
		mint()
		return
	}

	var cfg egress.Config
	cfg.Flags(flag.CommandLine)
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// BEFORE THE STORE, because the credential does not exist yet. Locking after
	// a secret is in memory locks it too late — the page it was written to may
	// already have been swapped.
	if err := egress.LockMemory(); err != nil {
		log.Error("refusing to serve", "error", err.Error())
		os.Exit(1)
	}

	// The credential store is required to SPEND, not to CONTAIN. A host running
	// only the firewall has no spend identity and should still serve: fail the
	// spend side closed with a refusing store rather than refusing to start.
	var store egress.Secrets
	store, close, err := egress.Vault(cfg)
	if err != nil {
		if cfg.ContainmentPath == "" {
			log.Error("cannot open the credential store", "error", err.Error())
			os.Exit(1)
		}
		log.Warn("no credential store; serving the firewall only, spend calls will refuse", "error", err.Error())
		store, close = egress.RefusingStore{}, func() {}
	}
	defer close()

	server, err := egress.New(cfg, store, log)
	if err != nil {
		log.Error("cannot serve", "error", err.Error())
		os.Exit(1)
	}
	log.Info("serving", "listen", cfg.Listen, "issuer", cfg.Issuer, "kms", cfg.KMS,
		"memory", "locked", "memory_encryption", egress.MemoryEncryption())
	if err := server.Listen(); err != nil {
		log.Error("stopped", "error", err.Error())
		os.Exit(1)
	}
}

// mint makes the pair this host is known by, and puts each half where it
// belongs in one step.
//
// The identity goes to STDOUT so it can be piped straight into the encrypted
// credential and never exist as a plaintext file:
//
//	egress mint | systemd-creds encrypt --with-key=host --name=identity - /etc/egress/identity.cred
//
// The recipient goes to STDERR so it is READ, not piped — it is the half that
// belongs in the environment file, in a manifest, in a commit. Splitting them
// across the two streams is what makes the safe thing the easy one: the pipe
// carries the secret straight into hardware, and the operator sees only the
// half that is safe to see.
func mint() {
	identity, recipient, err := kms.Recipient()
	if err != nil {
		fmt.Fprintln(os.Stderr, "egress: mint:", err)
		os.Exit(1)
	}
	fmt.Fprint(os.Stdout, identity)
	fmt.Fprintf(os.Stderr, "\nEGRESS_RECIPIENT=%s\n", recipient)
}
