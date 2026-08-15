package egress

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Credential is the upstream credential set, resolved from KMS and held in
// memory only.
//
// Nothing here is ever written down. The value exists in this process's heap and
// in KMS, and in no third place — no file, no environment variable, no
// Kubernetes Secret — which is the property the whole service exists to create.
//
// It refreshes on a timer rather than in the request path, so a proxied call
// never waits on KMS, and a value rewritten in KMS is in use within one interval
// with no redeploy and no restart. That is what makes rotation ordinary.
type Credential struct {
	kms      *KMS
	interval time.Duration
	log      Logger

	mu    sync.RWMutex
	value map[string]string
}

// NewCredential resolves every allowlisted upstream's credential once, and fails
// if any is missing. Starting without a credential would mean discovering the
// gap on a customer's request instead of at boot.
func NewCredential(ctx context.Context, kms *KMS, interval time.Duration, log Logger) (*Credential, error) {
	if interval <= 0 {
		interval = time.Minute
	}
	c := &Credential{kms: kms, interval: interval, log: log, value: map[string]string{}}
	for _, name := range Upstreams() {
		if err := c.refresh(ctx, upstreams[name].Secret); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Providers reports which upstreams egress can currently spend on. It answers
// with a name and whether a credential is held — never anything about the
// credential itself.
func (c *Credential) Providers() map[string]bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]bool, len(upstreams))
	for name, up := range upstreams {
		out[name] = c.value[up.Secret] != ""
	}
	return out
}

// Held reports how many credentials are in memory against how many the
// allowlist requires — what readiness and the metrics answer from.
func (c *Credential) Held() (held, want int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, v := range c.value {
		if v != "" {
			held++
		}
	}
	return held, len(upstreams)
}

// Value returns the credential for a secret reference. It never blocks on the
// network: the request path reads memory that the refresher keeps current.
func (c *Credential) Value(secret string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.value[secret]
	return v, ok && v != ""
}

// Watch refreshes every credential on the interval until ctx is done. Run it in
// its own goroutine; it is the only writer.
//
// A refresh that fails leaves the last good value in place and logs the reason.
// A KMS outage must not stop paid traffic that a still-valid credential can
// serve, and a credential that has genuinely been revoked fails at the vendor
// anyway — which is the correct place for that verdict.
func (c *Credential) Watch(ctx context.Context) {
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, name := range Upstreams() {
				secret := upstreams[name].Secret
				if err := c.refresh(ctx, secret); err != nil {
					c.log.Error("credential refresh failed, serving last known value", "secret", secret, "err", err)
				}
			}
		}
	}
}

// refresh reads one secret and replaces the held value. It reports a change
// without reporting the value, so a rotation is visible in the log and the
// credential is not.
func (c *Credential) refresh(ctx context.Context, secret string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	v, err := c.kms.Get(ctx, secret)
	if err != nil {
		return fmt.Errorf("credential %s: %w", secret, err)
	}

	c.mu.Lock()
	changed := c.value[secret] != v
	c.value[secret] = v
	c.mu.Unlock()

	if changed {
		c.log.Info("credential loaded", "secret", secret, "fingerprint", fingerprint(v))
	}
	return nil
}
