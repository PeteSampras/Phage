package novelty

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// validator is a small JSON Schema (2020-12) interpreter for exactly the
// keywords the novelty_finding schema uses. It refuses any keyword it does not
// implement, so a newer schema copied into testdata cannot be half-checked.
// It exists so the module needs no JSON Schema dependency.
type validator struct{}

var annotations = map[string]bool{
	"$schema": true, "$id": true, "title": true, "description": true,
}

func (validator) check(schema map[string]any, v any, path string) []string {
	var errs []string
	fail := func(format string, a ...any) { errs = append(errs, path+": "+fmt.Sprintf(format, a...)) }
	keys := make([]string, 0, len(schema))
	for k := range schema {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		kw := schema[k]
		switch {
		case annotations[k] || strings.HasPrefix(k, "x-"):
		case k == "type":
			if !hasType(v, kw.(string)) {
				fail("type %T, want %s", v, kw)
			}
		case k == "enum":
			found := false
			for _, e := range kw.([]any) {
				if e == v {
					found = true
				}
			}
			if !found {
				fail("%v not in enum %v", v, kw)
			}
		case k == "const":
			if v != kw {
				fail("%v != const %v", v, kw)
			}
		case k == "pattern":
			if s, ok := v.(string); ok && !regexp.MustCompile(kw.(string)).MatchString(s) {
				fail("%q does not match %s", s, kw)
			}
		case k == "minLength":
			if s, ok := v.(string); ok && utf8.RuneCountInString(s) < int(kw.(float64)) {
				fail("shorter than %v", kw)
			}
		case k == "maxLength":
			if s, ok := v.(string); ok && utf8.RuneCountInString(s) > int(kw.(float64)) {
				fail("longer than %v", kw)
			}
		case k == "minimum":
			if n, ok := v.(float64); ok && n < kw.(float64) {
				fail("%v < minimum %v", n, kw)
			}
		case k == "maximum":
			if n, ok := v.(float64); ok && n > kw.(float64) {
				fail("%v > maximum %v", n, kw)
			}
		case k == "format":
			if kw != "date-time" {
				panic("unimplemented format " + kw.(string))
			}
			if s, ok := v.(string); ok {
				if _, err := time.Parse(time.RFC3339Nano, s); err != nil {
					fail("not an RFC 3339 date-time: %q", s)
				}
			}
		case k == "required":
			if o, ok := v.(map[string]any); ok {
				for _, r := range kw.([]any) {
					if _, has := o[r.(string)]; !has {
						fail("missing required %q", r)
					}
				}
			}
		case k == "properties":
			if o, ok := v.(map[string]any); ok {
				for name, sub := range kw.(map[string]any) {
					if val, has := o[name]; has {
						errs = append(errs, validator{}.check(sub.(map[string]any), val, path+"."+name)...)
					}
				}
			}
		case k == "additionalProperties":
			if kw != false {
				panic("unimplemented additionalProperties form")
			}
			if o, ok := v.(map[string]any); ok {
				props, _ := schema["properties"].(map[string]any)
				for name := range o {
					if _, ok := props[name]; !ok {
						fail("additional property %q", name)
					}
				}
			}
		case k == "items":
			if a, ok := v.([]any); ok {
				for i, item := range a {
					errs = append(errs, validator{}.check(kw.(map[string]any), item, fmt.Sprintf("%s[%d]", path, i))...)
				}
			}
		case k == "allOf":
			for _, sub := range kw.([]any) {
				errs = append(errs, validator{}.check(sub.(map[string]any), v, path)...)
			}
		case k == "anyOf":
			ok := false
			for _, sub := range kw.([]any) {
				if len(validator{}.check(sub.(map[string]any), v, path)) == 0 {
					ok = true
				}
			}
			if !ok {
				fail("matches no anyOf branch")
			}
		case k == "not":
			if len(validator{}.check(kw.(map[string]any), v, path)) == 0 {
				fail("matches a `not` schema")
			}
		case k == "if":
			branch := "else"
			if len(validator{}.check(kw.(map[string]any), v, path)) == 0 {
				branch = "then"
			}
			if sub, ok := schema[branch].(map[string]any); ok {
				errs = append(errs, validator{}.check(sub, v, path)...)
			}
		case k == "then" || k == "else":
			// applied by "if"
		default:
			panic("schema keyword not implemented by the test validator: " + k)
		}
	}
	return errs
}

func hasType(v any, t string) bool {
	switch t {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "number":
		_, ok := v.(float64)
		return ok
	case "integer":
		n, ok := v.(float64)
		return ok && n == math.Trunc(n)
	case "boolean":
		_, ok := v.(bool)
		return ok
	}
	panic("unimplemented type " + t)
}

func loadJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return m
}

func schema(t *testing.T) map[string]any {
	return loadJSON(t, filepath.Join("testdata", "novelty_finding.v1.json"))
}

// validateRow marshals a row as the sink would and checks it against the
// schema.
func validateRow(t *testing.T, r Row) {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if errs := (validator{}).check(schema(t), m, "row"); len(errs) > 0 {
		t.Errorf("row does not satisfy novelty_finding.v1:\n  %s\n%s", strings.Join(errs, "\n  "), b)
	}
}

// The validator itself must agree with homelab-next's own fixtures: it accepts
// every example and rejects every negative.
func TestValidatorAgreesWithUpstreamFixtures(t *testing.T) {
	s := schema(t)
	ex, _ := filepath.Glob(filepath.Join("testdata", "examples", "*.json"))
	neg, _ := filepath.Glob(filepath.Join("testdata", "negative", "*.json"))
	if len(ex) == 0 || len(neg) == 0 {
		t.Fatal("testdata fixtures missing")
	}
	for _, p := range ex {
		if errs := (validator{}).check(s, loadJSON(t, p), "row"); len(errs) > 0 {
			t.Errorf("%s rejected: %v", p, errs)
		}
	}
	for _, p := range neg {
		if errs := (validator{}).check(s, loadJSON(t, p), "row"); len(errs) == 0 {
			t.Errorf("%s accepted, want rejected", p)
		}
	}
}
