// Copyright (C) 2019-2026, Hanzo Industries Inc. All rights reserved.

// Package containment runs egress's outbound network firewall: a transparent
// forward proxy with a default-deny host allowlist, a connect-time CIDR deny,
// DNS interception, TLS MITM or SNI passthrough, and the credential-transform
// pipeline. It is the connect half of egress — the spend half is /v1/call.
//
// The wiring is derived from iron-proxy (Apache-2.0; see NOTICE); its control,
// secret and audit planes are Hanzo's: policy comes from the config IAM
// distributes, secrets from KMS (the `kms` source, MPC-sharded), and the audit
// rides egress's own logger, which exports to o11y over ZAP.
package containment

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/hanzoai/egress/internal/certcache"
	iconfig "github.com/hanzoai/egress/internal/config"
	idns "github.com/hanzoai/egress/internal/dns"
	"github.com/hanzoai/egress/internal/dnsguard"
	"github.com/hanzoai/egress/internal/mcp"
	"github.com/hanzoai/egress/internal/mcpgateway"
	"github.com/hanzoai/egress/internal/proxy"
	"github.com/hanzoai/egress/internal/transform"

	// Register every transform. grpc is intentionally absent — it was an
	// external-plugin interface over the control-plane proto, which egress does
	// not carry.
	_ "github.com/hanzoai/egress/internal/transform/allowlist"
	_ "github.com/hanzoai/egress/internal/transform/annotate"
	_ "github.com/hanzoai/egress/internal/transform/awsauth"
	_ "github.com/hanzoai/egress/internal/transform/bodycapture"
	_ "github.com/hanzoai/egress/internal/transform/gcpauth"
	_ "github.com/hanzoai/egress/internal/transform/gcpidtoken"
	_ "github.com/hanzoai/egress/internal/transform/headerallowlist"
	_ "github.com/hanzoai/egress/internal/transform/hmacsign"
	_ "github.com/hanzoai/egress/internal/transform/judge"
	_ "github.com/hanzoai/egress/internal/transform/oauth"
	_ "github.com/hanzoai/egress/internal/transform/secrets"
)

// Runner holds the built firewall and serves it until Run's context is done.
type Runner struct {
	proxy *proxy.Proxy
	dns   *idns.Server
	log   *slog.Logger
}

// buildPipeline turns the configured transforms into the ordered pipeline the
// proxy runs on every request. An unknown transform name is a hard error — a
// firewall must not silently drop a rule it cannot understand.
func buildPipeline(transforms []iconfig.Transform, limits transform.BodyLimits, log *slog.Logger) (*transform.Pipeline, error) {
	var ts []transform.Transformer
	for _, tc := range transforms {
		factory, err := transform.Lookup(tc.Name)
		if err != nil {
			return nil, fmt.Errorf("unknown transform %q: %w", tc.Name, err)
		}
		t, err := factory(tc.Config, log)
		if err != nil {
			return nil, fmt.Errorf("initializing transform %q: %w", tc.Name, err)
		}
		ts = append(ts, t)
	}
	return transform.NewPipeline(ts, limits, log), nil
}

// New assembles the firewall from config. The audit rides log, so whatever
// exporter egress attaches to its logger (o11y over ZAP) receives every
// per-request record.
func New(cfg *iconfig.Config, log *slog.Logger) (*Runner, error) {
	limits := transform.BodyLimits{
		MaxRequestBodyBytes:  cfg.Proxy.MaxRequestBodyBytes,
		MaxResponseBodyBytes: cfg.Proxy.MaxResponseBodyBytes,
	}
	pipeline, err := buildPipeline(cfg.Transforms, limits, log)
	if err != nil {
		return nil, err
	}
	pipeline.SetAuditFunc(transform.AuditFunc(transform.NewAuditLogger(log)))
	holder := transform.NewPipelineHolder(pipeline)

	mcpPolicy, err := mcp.LoadFromNode(cfg.MCP)
	if err != nil {
		return nil, fmt.Errorf("mcp policy: %w", err)
	}
	gateway, err := mcpgateway.LoadFromNode(cfg.MCPGateway)
	if err != nil {
		return nil, fmt.Errorf("mcp gateway: %w", err)
	}

	var certCache *certcache.Cache
	if cfg.TLS.Mode != iconfig.TLSModeSNIOnly {
		leafExpiry := time.Duration(cfg.TLS.LeafCertExpiryHours) * time.Hour
		certCache, err = certcache.New(cfg.TLS.CACert, cfg.TLS.CAKey, cfg.TLS.CertCacheSize, leafExpiry)
		if err != nil {
			return nil, fmt.Errorf("cert cache: %w", err)
		}
	}

	resolver := net.DefaultResolver
	if cfg.DNS.UpstreamResolver != "" {
		resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", cfg.DNS.UpstreamResolver)
		}}
	}

	var dnsServer *idns.Server
	if cfg.DNS.IsEnabled() {
		if dnsServer, err = idns.New(cfg.DNS, resolver, log); err != nil {
			return nil, fmt.Errorf("dns server: %w", err)
		}
	}

	guard, err := dnsguard.New(cfg.Proxy.UpstreamDenyCIDRs.Values)
	if err != nil {
		return nil, fmt.Errorf("upstream deny guard: %w", err)
	}

	p := proxy.New(proxy.Options{
		HTTPAddr:                      cfg.Proxy.HTTPListen,
		HTTPSAddr:                     cfg.Proxy.HTTPSListen,
		TunnelAddr:                    cfg.Proxy.TunnelListen,
		TLSMode:                       cfg.TLS.Mode,
		CertCache:                     certCache,
		Pipeline:                      holder,
		Resolver:                      resolver,
		Guard:                         guard,
		MCPPolicy:                     mcp.NewPolicyHolder(mcpPolicy),
		MCPGateway:                    mcpgateway.NewHolder(gateway),
		Logger:                        log,
		UpstreamResponseHeaderTimeout: time.Duration(cfg.Proxy.UpstreamResponseHeaderTimeout),
		UpstreamProxy:                 cfg.Proxy.UpstreamProxy.ProxyFunc(),
	})

	return &Runner{proxy: p, dns: dnsServer, log: log}, nil
}

// Run serves the proxy (and DNS, when enabled) until ctx is done or a listener
// fails. It returns the first fatal error.
func (r *Runner) Run(ctx context.Context) error {
	errc := make(chan error, 2)
	if r.dns != nil {
		go func() { errc <- fmt.Errorf("dns: %w", r.dns.ListenAndServe()) }()
	}
	go func() { errc <- fmt.Errorf("proxy: %w", r.proxy.ListenAndServe()) }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errc:
		return err
	}
}
