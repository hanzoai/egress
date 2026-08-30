// Copyright (C) 2019-2026, Hanzo Industries Inc. All rights reserved.

package secrets

import (
	"context"
	"fmt"
	"log/slog"

	"gopkg.in/yaml.v3"
)

// KMSFetcher reads a secret out of Hanzo KMS by its custody reference. The
// value is MPC-sharded and sealed at rest; the transform holds it only for the
// life of one request, never returns it, and never writes it to a log. egress
// injects this at startup with SetKMSFetcher — the secrets package does not
// depend on the KMS SDK, so a build that never configures KMS drops the source
// cleanly rather than dragging the client.
type KMSFetcher func(ctx context.Context, ref string) (string, error)

var kmsFetch KMSFetcher

// SetKMSFetcher wires the KMS custody read that the `kms` source uses. Called
// once at composition, before the pipeline is built.
func SetKMSFetcher(f KMSFetcher) { kmsFetch = f }

type kmsConfig struct {
	Ref        string `yaml:"ref"`
	TTL        string `yaml:"ttl"`
	FailureTTL string `yaml:"failure_ttl"`
}

type kmsBuilder struct{ logger *slog.Logger }

func newKMSBuilder(logger *slog.Logger) *kmsBuilder { return &kmsBuilder{logger: logger} }

func (r *kmsBuilder) Build(raw yaml.Node) (secretSource, error) {
	var cfg kmsConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing kms source config: %w", err)
	}
	if cfg.Ref == "" {
		return nil, fmt.Errorf("kms source requires \"ref\" field")
	}
	return buildLazySource(cfg.Ref, cfg.TTL, cfg.FailureTTL, r.logger, func(ctx context.Context) (string, error) {
		if kmsFetch == nil {
			return "", fmt.Errorf("kms source used but no KMS custody is configured")
		}
		v, err := kmsFetch(ctx, cfg.Ref)
		if err != nil {
			return "", fmt.Errorf("reading kms ref %q: %w", cfg.Ref, err)
		}
		if v == "" {
			return "", fmt.Errorf("kms ref %q is empty", cfg.Ref)
		}
		return v, nil
	})
}
