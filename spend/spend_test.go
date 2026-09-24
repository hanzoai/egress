package spend

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// fetchOf is the Fetch the carrier would send for r, as bytes.
func fetchOf(t *testing.T, cfg Config, r *http.Request) string {
	t.Helper()
	in, err := describe(cfg, r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A JSON cloud's calls are described byte for byte as they always were: no
// field this package learned for AWS appears on them.
func TestAJSONCallIsDescribedAsItAlwaysWas(t *testing.T) {
	cfg := Config{Provider: "DigitalOcean", Account: "prod"}

	post, _ := http.NewRequest(http.MethodPost, "https://api.digitalocean.com/v2/droplets",
		strings.NewReader(`{"name":"web-1","size":"s-1vcpu-1gb"}`))
	post.Header.Set("Content-Type", "application/json")
	if got, want := fetchOf(t, cfg, post),
		`{"provider":"DigitalOcean","label":"prod","method":"POST","path":"/v2/droplets","body":{"name":"web-1","size":"s-1vcpu-1gb"}}`; got != want {
		t.Errorf("POST\n got %s\nwant %s", got, want)
	}

	get, _ := http.NewRequest(http.MethodGet, "https://api.digitalocean.com/v2/droplets?page=2", nil)
	if got, want := fetchOf(t, cfg, get),
		`{"provider":"DigitalOcean","label":"prod","method":"GET","path":"/v2/droplets?page=2","body":null}`; got != want {
		t.Errorf("GET\n got %s\nwant %s", got, want)
	}

	// A JSON body with no Content-Type is how an SDK that never set one called.
	bare, _ := http.NewRequest(http.MethodPut, "https://api.hetzner.cloud/v1/servers/1", strings.NewReader(`{"name":"a"}`))
	if got := fetchOf(t, Config{Provider: "Hetzner"}, bare); strings.Contains(got, `"raw"`) || strings.Contains(got, `"type"`) {
		t.Errorf("a JSON body grew raw fields: %s", got)
	}
}

// A body that is not JSON travels as bytes with its own Content-Type, and an
// AWS call carries the endpoint it was addressed to, lowercased and without a
// port. Nothing else does.
func TestAFormTravelsAsBytesAndAWSNamesItsEndpoint(t *testing.T) {
	form := "Action=RunInstances&Version=2016-11-15&ImageId=ami-0045d7fc2ad003464"
	r, _ := http.NewRequest(http.MethodPost, "https://EC2.us-east-1.amazonaws.com:443/", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	in, err := describe(Config{Provider: "AWS", Account: "hanzo-compute"}, r)
	if err != nil {
		t.Fatal(err)
	}
	if string(in.Raw) != form || in.Type != "application/x-www-form-urlencoded; charset=utf-8" || in.Body != nil {
		t.Fatalf("form described as %+v", in)
	}
	if in.Host != "ec2.us-east-1.amazonaws.com" || in.Label != "hanzo-compute" || in.Path != "/" {
		t.Fatalf("aws call described as %+v", in)
	}

	r, _ = http.NewRequest(http.MethodPost, "https://api.digitalocean.com/v2/x", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if in, _ := describe(Config{Provider: "DigitalOcean"}, r); in.Host != "" || in.Type == "" {
		t.Fatalf("a bearer cloud named a host, or its form lost its type: %+v", in)
	}

	// JSON under a type that is not application/json is carried with its type.
	r, _ = http.NewRequest(http.MethodPost, "https://dynamodb.us-east-1.amazonaws.com/", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/x-amz-json-1.0")
	if in, _ := describe(Config{Provider: "AWS"}, r); in.Type != "application/x-amz-json-1.0" || string(in.Raw) != `{}` {
		t.Fatalf("typed JSON described as %+v", in)
	}
}

// What an SDK reads back: the cloud's own bytes and type when egress carried
// them as bytes, JSON otherwise.
func TestAnAnswerIsRebuiltAsTheCloudSentIt(t *testing.T) {
	r, _ := http.NewRequest(http.MethodPost, "https://ec2.us-east-1.amazonaws.com/", nil)
	xml := answer(r, Fetched{Status: 400, Raw: []byte("<Response/>"), Type: "text/xml;charset=UTF-8"})
	read, _ := io.ReadAll(xml.Body)
	if xml.StatusCode != 400 || xml.Header.Get("Content-Type") != "text/xml;charset=UTF-8" || string(read) != "<Response/>" {
		t.Fatalf("xml answer = %d %q %s", xml.StatusCode, xml.Header.Get("Content-Type"), read)
	}
	empty := answer(r, Fetched{Status: 204, Type: "text/xml"})
	if read, _ := io.ReadAll(empty.Body); len(read) != 0 || empty.Header.Get("Content-Type") != "text/xml" {
		t.Fatalf("an empty raw answer = %q %s", empty.Header.Get("Content-Type"), read)
	}
	js := answer(r, Fetched{Status: 200, Body: json.RawMessage(`{"a":1}`)})
	if read, _ := io.ReadAll(js.Body); string(read) != `{"a":1}` || js.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("json answer = %q %s", js.Header.Get("Content-Type"), read)
	}
	// And a JSON answer is the same bytes as before.
	b, _ := json.Marshal(Fetched{Status: 200, Body: json.RawMessage(`{"a":1}`), Scope: "org", Millis: 3})
	if string(b) != `{"status":200,"body":{"a":1},"scope":"org","millis":3}` {
		t.Fatalf("Fetched = %s", b)
	}
}
