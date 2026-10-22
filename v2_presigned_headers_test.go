package awsig

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestV2PresignedQueryHeaders(t *testing.T) {
	now := time.Date(2026, time.September, 23, 0, 0, 0, 0, time.UTC)
	expires := strconv.FormatInt(now.Add(time.Hour).Unix(), 10)
	for _, combined := range []bool{false, true} {
		for _, mixedCase := range []bool{false, true} {
			for _, mutation := range []string{"", "token", "acl", "type", "md5", "duplicate", "case-alias", "conflict", "identical-header", "legacy-provider"} {
				t.Run(strconv.FormatBool(combined)+"/"+strconv.FormatBool(mixedCase)+"/"+mutation, func(t *testing.T) {
					q := url.Values{"AWSAccessKeyId": {"key"}, "Expires": {expires}}
					values := map[string]string{"x-amz-security-token": "valid-token", "x-amz-acl": "private", "content-type": "text/plain", "content-md5": "1B2M2Y8AsgTpgAmY7PhCfg=="}
					for key, value := range values {
						if mixedCase {
							key = http.CanonicalHeaderKey(key)
						}
						q.Set(key, value)
					}
					// Independently sign the headers before moving them into the query,
					// as botocore's HmacV1QueryAuth does.
					mac := hmac.New(sha1.New, []byte("secret"))
					_, _ = mac.Write([]byte("PUT\n1B2M2Y8AsgTpgAmY7PhCfg==\ntext/plain\n" + expires + "\nx-amz-acl:private\nx-amz-security-token:valid-token\n/bucket/key"))
					q.Set("Signature", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
					name := func(key string) string {
						if mixedCase {
							return http.CanonicalHeaderKey(key)
						}
						return key
					}
					switch mutation {
					case "token":
						q.Set(name("x-amz-security-token"), "other-token")
					case "acl":
						q.Set(name("x-amz-acl"), "public-read")
					case "type":
						q.Set(name("content-type"), "application/json")
					case "md5":
						q.Set(name("content-md5"), "changed")
					case "duplicate":
						q.Add(name("x-amz-security-token"), "valid-token")
					case "case-alias":
						q.Set(strings.ToUpper("x-amz-security-token"), "valid-token")
					}
					r := httptest.NewRequest(http.MethodPut, "https://example.com/bucket/key?"+q.Encode(), nil)
					if mutation == "conflict" {
						r.Header.Set("Content-Type", "application/json")
					}
					if mutation == "identical-header" {
						r.Header.Set("Content-Type", "text/plain")
					}
					original := r.Header.Clone()
					// Accept both tokens here to prove the signature binds the token even
					// when the provider returns the same secret for either one.
					var provider CredentialsProvider[string] = presignedTokenProvider{}
					if mutation == "legacy-provider" {
						provider = tokenlessProvider{}
					}
					v := NewV2V4(provider, V4Config{})
					v.v2.now = func() time.Time { return now }
					var err error
					if combined {
						_, err = v.Verify(r, "")
					} else {
						_, err = v.v2.Verify(r, "")
					}
					var want error
					switch mutation {
					case "", "identical-header":
					case "duplicate", "case-alias":
						want = ErrInvalidToken
					case "conflict":
						want = ErrInvalidRequest
					case "legacy-provider":
						want = ErrInvalidToken
					default:
						want = ErrSignatureDoesNotMatch
					}
					if !errors.Is(err, want) {
						t.Fatalf("got %v, want %v", err, want)
					}
					if !reflect.DeepEqual(original, r.Header) {
						t.Fatal("verification mutated request headers")
					}
				})
			}
		}
	}
}

type presignedTokenProvider struct{ tokenlessProvider }

func (presignedTokenProvider) ProvideWithToken(context.Context, string, string) (string, string, error) {
	return "secret", "user", nil
}

func TestV2PresignedRejectsAddedToken(t *testing.T) {
	now := time.Date(2026, time.September, 23, 0, 0, 0, 0, time.UTC)
	for _, name := range []string{"x-amz-security-token", "X-Amz-Security-Token"} {
		r := sessionRequest(t, 2, "query", "", now)
		q := r.URL.Query()
		q.Set(name, "invalid-token")
		r.URL.RawQuery = q.Encode()
		v := NewV2(tokenlessProvider{})
		v.now = func() time.Time { return now }
		if _, err := v.Verify(r, ""); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("%s: got %v, want ErrInvalidToken", name, err)
		}
	}
}

func TestV2PresignedRejectsHeaderInjection(t *testing.T) {
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	expires := strconv.FormatInt(now.Add(time.Hour).Unix(), 10)
	q := url.Values{"AWSAccessKeyId": {"key"}, "Expires": {expires}, "x-amz-meta-a": {"one"}, "x-amz-meta-b": {"two"}}
	mac := hmac.New(sha1.New, []byte("secret"))
	mac.Write([]byte("PUT\n\n\n" + expires + "\nx-amz-meta-a:one\nx-amz-meta-b:two\n/bucket/key"))
	q.Set("Signature", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	v := NewV2(tokenlessProvider{})
	v.now = func() time.Time { return now }
	for _, mutate := range []bool{false, true} {
		if mutate {
			q.Set("x-amz-meta-a", "one\nx-amz-meta-b:two")
			q.Del("x-amz-meta-b")
		}
		r := httptest.NewRequest("PUT", "https://example.com/bucket/key?"+q.Encode(), nil)
		_, err := v.Verify(r, "")
		if !mutate && err != nil {
			t.Fatalf("valid request: %v", err)
		}
		if mutate && !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("modified request: got %v, want ErrInvalidRequest", err)
		}
	}
}

func TestV2PresignedQueryHeaderSyntax(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		valid       bool
	}{
		{"x-amz-meta-note", "plain text", true},
		{"X-Amz-Meta-Note", "tab\tand café", true},
		{"x-amz-meta-note", "", true},
		{"x-amz-meta-note", "one\ntwo", false},
		{"x-amz-meta-note", "one\rtwo", false},
		{"x-amz-meta-note", "one\x00two", false},
		{"content-type", "text/plain\x7f", false},
		{"content-md5", "checksum\v", false},
		{"x-amz-meta-a:b", "value", false},
		{"x-amz-meta-a\nb", "value", false},
		{"x-amz-meta-a b", "value", false},
		{"x-amz-meta-K", "value", false},
	} {
		t.Run(tc.name+"/"+tc.value, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "https://example.com/bucket/key", nil)
			q := url.Values{tc.name: {tc.value}}
			_, err := v2PresignedRequest(r, q)
			if tc.valid && err != nil {
				t.Fatal(err)
			}
			if !tc.valid && !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("got %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestV2PresignedWhitespace(t *testing.T) {
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	expires := strconv.FormatInt(now.Add(time.Hour).Unix(), 10)
	for _, tc := range []struct{ name, value, canonical string }{
		{"x-amz-meta-note", "  hello\t", "PUT\n\n\n" + expires + "\nx-amz-meta-note:hello\n/bucket/key"},
		{"content-type", " text/plain ", "PUT\n\ntext/plain\n" + expires + "\n/bucket/key"},
	} {
		for _, header := range []string{"", "trimmed", "spaced", "conflicting"} {
			for _, spaced := range []bool{false, true} {
				value := strings.TrimSpace(tc.value)
				if spaced {
					value = tc.value
				}
				q := url.Values{"AWSAccessKeyId": {"key"}, "Expires": {expires}, tc.name: {value}}
				mac := hmac.New(sha1.New, []byte("secret"))
				mac.Write([]byte(tc.canonical))
				q.Set("Signature", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
				r := httptest.NewRequest("PUT", "https://example.com/bucket/key?"+q.Encode(), nil)
				switch header {
				case "trimmed":
					r.Header.Set(tc.name, strings.TrimSpace(tc.value))
				case "spaced":
					r.Header.Set(tc.name, tc.value)
				case "conflicting":
					r.Header.Set(tc.name, "different")
				}
				original := r.Header.Clone()
				v := NewV2(tokenlessProvider{})
				v.now = func() time.Time { return now }
				_, err := v.Verify(r, "")
				var want error
				if header == "conflicting" {
					want = ErrInvalidRequest
				}
				if !errors.Is(err, want) {
					t.Errorf("%s spaced=%v header=%s: got %v, want %v", tc.name, spaced, header, err, want)
				}
				if !reflect.DeepEqual(original, r.Header) {
					t.Fatal("request headers mutated")
				}
			}
		}
	}
}
