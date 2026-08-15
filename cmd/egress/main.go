// Command egress runs the outbound trust boundary.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hanzoai/egress"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := run(log); err != nil {
		log.Error("egress stopped", "err", err)
		os.Exit(1)
	}
}

func run(log egress.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Shut the two paths by which a value in memory reaches a disk on its own.
	// Core dumps are always closed; locking pages needs a memlock allowance the
	// pod may not have, so a failure is reported rather than fatal — Kubernetes
	// runs with swap off, which is the guarantee this reinforces rather than
	// replaces. Reported, because a silent downgrade of a stated property is
	// worse than not stating it.
	if err := egress.Confine(); err != nil {
		log.Warn("memory not locked; relying on swap being off", "err", err)
	} else {
		log.Info("memory locked, core dumps disabled")
	}

	kms, err := egress.NewKMS(
		env("EGRESS_KMS", "https://kms.hanzo.ai"),
		env("EGRESS_KMS_ID", ""),
		env("EGRESS_KMS_SECRET", ""),
		env("EGRESS_KMS_ENV", "prod"),
		nil,
	)
	if err != nil {
		return err
	}

	// Callers prove themselves with the projected service-account token the
	// kubelet mints for them and rotates, and the cluster is asked what each one
	// means. No caller holds a standing credential for this service, so there is
	// nothing on a caller's side worth stealing to spend here.
	cluster, err := egress.Cluster()
	if err != nil {
		return err
	}
	identity, err := egress.NewIdentity(
		env("EGRESS_CLUSTER", "https://kubernetes.default.svc"),
		env("EGRESS_AUDIENCE", "egress"),
		egress.ParseGrants(env("EGRESS_GRANTS", "")),
		cluster,
	)
	if err != nil {
		return err
	}

	// Resolving every credential before the listener opens is the fail-closed
	// half of this: a boot that cannot reach KMS never accepts a request it
	// would have to refuse.
	cred, err := egress.NewCredential(ctx, kms, duration(env("EGRESS_REFRESH", "60s")), log)
	if err != nil {
		return err
	}
	go cred.Watch(ctx)

	addr := env("EGRESS_ADDR", ":8080")
	srv := &http.Server{
		Addr:    addr,
		Handler: egress.New(identity, cred, log),
		// Bound the header phase against a client that opens a connection and
		// dawdles. The write side is deliberately unbounded: a streamed
		// completion is a long, legitimate response.
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	done := make(chan error, 1)
	go func() {
		log.Info("egress listening", "addr", addr, "upstreams", egress.Upstreams())
		done <- srv.ListenAndServe()
	}()

	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		log.Info("draining")
		shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func duration(v string) time.Duration {
	d, err := time.ParseDuration(v)
	if err != nil {
		return time.Minute
	}
	return d
}
