// Copyright 2023-2025 Hanzo AI Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package egress

import (
	"os"
	"strings"
	"testing"
)

// The example is the deployment: it is copied to /etc/egress/env by hand, so a
// wrong value in it is a wrong value in production.
//
// This one is worth a test because of WHEN it fails. A JWKS document is fetched
// on the first call, not at boot, so the root spelling — which answers 404 —
// starts a healthy-looking process that then refuses every caller as
// unidentifiable. That reads like a token problem and sends the search to IAM,
// which is the expensive place to look for a typo that lives here.
func TestExampleJWKSIsTheIAMPrefixedURL(t *testing.T) {
	raw, err := os.ReadFile("deploy/env.example")
	if err != nil {
		t.Fatal(err)
	}
	var jwks string
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "EGRESS_JWKS="); ok {
			jwks = v
			break
		}
	}
	if jwks == "" {
		t.Fatal("no EGRESS_JWKS in deploy/env.example")
	}
	if !strings.Contains(jwks, "/v1/iam/.well-known/jwks") {
		t.Errorf("EGRESS_JWKS = %q; IAM publishes its key set under /v1/iam/, and the host root 404s", jwks)
	}
}
