package egress

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hanzoai/jwt"
)

// program mints the token IAM's client_credentials grant produces, claim for
// claim: the subject is the APPLICATION ROW's address — `admin/<client>`, where
// `admin` is the reserved org every application is filed under — while `owner`
// is the tenant the program acts for. The two disagreeing is the normal case,
// not an edge one.
func program(t *testing.T, key jwt.Key, client, org string) string {
	t.Helper()
	return token(t, key, func(c *jwt.Claims) {
		c.Type = jwt.Program
		c.Azp = client
		c.Owner = org
		c.Name = client
		c.Subject, c.Id = "admin/"+client, ""
	})
}

// TestAProgramIsSpentForItsTenantAndNotForAdmin is the reserved-org reading.
//
// A program's subject reads `admin/hanzo-egress`. `admin` there is where the
// APPLICATION is filed, and it is also the one org that means platform sudo.
// Anything that reaches into the subject for a tenant roots every program in it
// — one path, holding every machine's credentials, named after the org whose
// membership is the estate's cross-tenant authority.
func TestAProgramIsSpentForItsTenantAndNotForAdmin(t *testing.T) {
	key := issuerKey(t)
	p, err := verifier(t, key).Verify(context.Background(),
		"Bearer "+program(t, key, audience, "hanzo"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Org != "hanzo" {
		t.Errorf("org = %q, want the tenant hanzo", p.Org)
	}
	if p.Org == "admin" {
		t.Fatal("a program was rooted in the reserved org")
	}
	if p.Kind != Programs {
		t.Errorf("kind = %q, want %q", p.Kind, Programs)
	}
	if p.Name != audience {
		t.Errorf("name = %q, want the client id %q", p.Name, audience)
	}
	if got, want := ownRef(p, "openai", "default"),
		"orgs/hanzo/apps/hanzo-egress/connectors/openai/default"; got != want {
		t.Errorf("custody path = %q, want %q", got, want)
	}
}

// TestAChosenNameCannotReachAnotherPrincipalsCredentials is the attack on the
// scheme itself.
//
// Both halves of a name are attacker-chosen: anyone may register an account, and
// whoever registers an application picks its client id. A scheme that FLATTENS
// the two classes into one path segment has to keep two chosen values from
// meeting, and the obvious flattening — a program's `admin/hanzo-egress` with the
// slash rewritten to the separator the segment rule already allows — puts them
// exactly one registration apart: an account named `admin-hanzo-egress` lands on
// the path holding a program's provider keys, and enrolling under it overwrites
// what that program spends.
//
// So this walks the collisions rather than trusting the argument, and asserts the
// property that makes them impossible: no two distinct principals share a path.
func TestAChosenNameCannotReachAnotherPrincipalsCredentials(t *testing.T) {
	key := issuerKey(t)
	v := verifier(t, key)

	// Each pair is a name picked to land on the one before it once a scheme
	// flattens the class away.
	callers := map[string]string{
		"the program":                  program(t, key, audience, "hanzo"),
		"an account named like it":     token(t, key, person("hanzo", "hanzo-egress")),
		"an account named like its id": token(t, key, person("hanzo", "admin-hanzo-egress")),
		"a program named like a person": program(t, key,
			"b474eaa5-e000-474d-b317-c37bbd9a6945", "hanzo"),
		"the person it is named after": token(t, key,
			person("hanzo", "b474eaa5-e000-474d-b317-c37bbd9a6945")),
		"the same names, another tenant":     program(t, key, audience, "acme"),
		"an account in that other tenant":    token(t, key, person("acme", "hanzo-egress")),
		"a program under the reserved org":   program(t, key, audience, "admin"),
		"an account under the reserved org":  token(t, key, person("admin", "hanzo-egress")),
		"a program whose client is a tenant": program(t, key, "hanzo", "hanzo"),
	}

	seen := map[string]string{}
	for who, raw := range callers {
		p, err := v.Verify(context.Background(), "Bearer "+raw)
		if err != nil {
			t.Errorf("%s: refused (%v)", who, err)
			continue
		}
		// Every route a credential is addressed by, not just the read path.
		for _, ref := range []string{
			ownRef(p, "openai", "default"),
			ownRef(p, "anthropic", "default"),
		} {
			if other, clash := seen[ref]; clash {
				t.Errorf("COLLISION: %s and %s both address %s", who, other, ref)
				continue
			}
			seen[ref] = who
		}
	}
}

// TestTheClaimShapeIsTheOneIAMSends is the production reading, held offline.
//
// These are the claims hanzo.id puts in a live access token — the set, and the
// spellings. `id` is not among them: the token states `sub` and stops there. A
// verifier reading `id` for the subject therefore finds nothing on every real
// token, and an empty subject is refused, so it answers "not identified" to the
// whole estate while its own fixtures — which carried an `id` no issuer sends —
// went on passing.
func TestTheClaimShapeIsTheOneIAMSends(t *testing.T) {
	const live = `{
	  "iss": "https://hanzo.id",
	  "sub": "b474eaa5-e000-474d-b317-c37bbd9a6945",
	  "aud": ["hanzo-egress"],
	  "azp": "hanzo-cli",
	  "owner": "hanzo",
	  "organization": "hanzo",
	  "name": "a",
	  "preferred_username": "a",
	  "scope": "openid profile email",
	  "tokenType": "access-token"
	}`
	var c jwt.Claims
	if err := json.Unmarshal([]byte(live), &c); err != nil {
		t.Fatal(err)
	}
	if c.Id != "" {
		t.Fatal("the fixture carries an id the issuer does not send")
	}
	p, err := identify(&c)
	if err != nil {
		t.Fatalf("a live token was refused: %v", err)
	}
	want := Principal{
		Org:  "hanzo",
		Kind: Persons,
		Name: "b474eaa5-e000-474d-b317-c37bbd9a6945",
	}
	if p != want {
		t.Fatalf("principal = %+v, want %+v", p, want)
	}
}

// An issuer that states the subject under the other spelling is read the same
// way. Both name the subject; neither is the username.
func TestTheOtherSpellingOfTheSubjectIsRead(t *testing.T) {
	p, err := identify(&jwt.Claims{User: &jwt.User{Owner: "acme", Id: "u-7"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "u-7" || p.Kind != Persons {
		t.Fatalf("principal = %+v", p)
	}
}

// person builds the claims IAM mints for an account: a subject and no class at
// all. The name is carried too, because a scheme that reached for it instead of
// the subject would pass every other test in this file.
func person(org, subject string) func(*jwt.Claims) {
	return func(c *jwt.Claims) {
		c.Owner = org
		c.Name = subject
		c.Subject, c.Id = subject, ""
		c.Type = ""
	}
}

// TestTheClassIsNotSomethingACallerCanClaim pins where the class comes from.
// It is signed, and the signature is checked before anything here reads it — so
// this asserts the reading, not the cryptography: a token that says nothing about
// its class is a person, and only the issuer's own word moves it.
func TestTheClassIsNotSomethingACallerCanClaim(t *testing.T) {
	key := issuerKey(t)
	v := verifier(t, key)

	// Every claim that has ever been used to GUESS the class, set to what a
	// program's token carries — with the class itself left unsaid.
	for name, edit := range map[string]func(*jwt.Claims){
		"a subject shaped like a program's": func(c *jwt.Claims) {
			c.Subject, c.Id = "admin/"+audience, ""
		},
		"a client id equal to the audience": func(c *jwt.Claims) { c.Azp = audience },
		"a username equal to the audience":  func(c *jwt.Claims) { c.Name = audience },
	} {
		t.Run(name, func(t *testing.T) {
			p, err := v.Verify(context.Background(), "Bearer "+token(t, key, edit))
			if err != nil {
				// A subject with a slash is refused outright, which is also a
				// non-answer to "is this a program". Either way it is not one.
				return
			}
			if p.Kind != Persons {
				t.Fatalf("kind = %q — the class was inferred from a claim the "+
					"caller's own registration decides", p.Kind)
			}
		})
	}
}

// TestATenantStillCannotBeNamedByTheCaller keeps the original boundary while the
// path gains a segment: the org comes from the signed claim, never the subject.
func TestATenantStillCannotBeNamedByTheCaller(t *testing.T) {
	key := issuerKey(t)
	v := verifier(t, key)

	for name, edit := range map[string]func(*jwt.Claims){
		"a subject naming another tenant": func(c *jwt.Claims) {
			c.Subject, c.Id = "victim/u-7", ""
		},
		"a program subject naming another tenant": func(c *jwt.Claims) {
			c.Type, c.Azp = jwt.Program, audience
			c.Subject, c.Id = "victim/"+audience, ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, err := v.Verify(context.Background(), "Bearer "+token(t, key, edit))
			if err != nil {
				return
			}
			if p.Org != "acme" {
				t.Fatalf("org = %q — a tenant was read out of the subject", p.Org)
			}
		})
	}
}
