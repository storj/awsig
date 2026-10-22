package awsig

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

type sessionProvider struct {
	calls     int
	lastToken string
}

func (*sessionProvider) Provide(context.Context, string) (string, string, error) {
	return "", "", errors.New("token-aware provider was bypassed")
}
func (p *sessionProvider) ProvideWithToken(_ context.Context, key, token string) (string, string, error) {
	p.calls++
	p.lastToken = token
	if key != "key" {
		return "", "", ErrInvalidAccessKeyID
	}
	if token != "valid-token" {
		return "", "", ErrInvalidToken
	}
	return "secret", "session-user", nil
}

type tokenlessProvider struct{}

func (tokenlessProvider) Provide(context.Context, string) (string, string, error) {
	return "secret", "user", nil
}

func sessionRequest(t *testing.T, version int, mode, token string, now time.Time, extraTokens ...string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "https://example.com/bucket/key", nil)
	v2 := NewV2[string](nil)
	v4 := NewV4[string](nil, V4Config{Region: "us-east-1", Service: "s3"})
	date := now.UTC().Format(timeFormatISO8601)
	sc := scope{date: date[:8], region: "us-east-1", service: "s3"}
	credential := "key/" + sc.String()
	if mode == "POST" {
		form := map[string]string{"policy": "e30="}
		if token != "" {
			form[queryXAmzSecurityToken] = token
		}
		if version == 2 {
			form[queryAWSAccessKeyId] = "key"
			form[querySignature] = v2.calculatePostSignature(form["policy"], "secret").String()
		} else {
			form[queryXAmzAlgorithm] = "AWS4-HMAC-SHA256"
			form[queryXAmzCredential] = credential
			form[queryXAmzDate] = date
			form[queryXAmzSignature] = v4.calculatePostSignature(signatureV4Data{scope: sc, digest: []byte(form["policy"])}, "secret").String()
		}
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		for k, v := range form {
			if err := mw.WriteField(k, v); err != nil {
				t.Fatal(err)
			}
		}
		for _, extra := range extraTokens {
			if err := mw.WriteField(queryXAmzSecurityToken, extra); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := mw.CreateFormFile("file", "test.txt"); err != nil {
			t.Fatal(err)
		}
		if err := mw.Close(); err != nil {
			t.Fatal(err)
		}
		r = httptest.NewRequest(http.MethodPost, "https://example.com/bucket", &body)
		r.Header.Set("Content-Type", mw.FormDataContentType())
		return r
	}
	if mode == "query" {
		q := url.Values{}
		if token != "" {
			q.Set(queryXAmzSecurityToken, token)
		}
		for _, extra := range extraTokens {
			q.Add(queryXAmzSecurityToken, extra)
		}
		if version == 2 {
			expires := strconv.FormatInt(now.Add(time.Hour).Unix(), 10)
			q.Set(queryExpires, expires)
			q.Set(queryAWSAccessKeyId, "key")
			r.URL.RawQuery = q.Encode()
			if token != "" {
				r.Header.Set(queryXAmzSecurityToken, token)
			}
			for _, extra := range extraTokens {
				r.Header.Add(queryXAmzSecurityToken, extra)
			}
			q.Set(querySignature, v2.calculateSignature(r, r.URL.Query(), expires, "", "secret").String())
			r.Header.Del(queryXAmzSecurityToken)
		} else {
			q.Set(queryXAmzAlgorithm, "AWS4-HMAC-SHA256")
			q.Set(queryXAmzCredential, credential)
			q.Set(queryXAmzDate, date)
			q.Set(queryXAmzExpires, "3600")
			q.Set(queryXAmzSignedHeaders, "host")
			sig := calculateSignatureV4(signatureV4Data{dateTime: date, scope: sc, digest: v4.canonicalRequestHash(r, q, []string{"host"}, unsignedPayload)}, "secret")
			q.Set(queryXAmzSignature, sig.String())
		}
		r.URL.RawQuery = q.Encode()
		return r
	}
	if token != "" {
		r.Header.Set(queryXAmzSecurityToken, token)
	}
	for _, extra := range extraTokens {
		r.Header.Add(queryXAmzSecurityToken, extra)
	}
	if version == 2 {
		httpDate := now.UTC().Format(http.TimeFormat)
		r.Header.Set("Date", httpDate)
		r.Header.Set("Authorization", "AWS key:"+v2.calculateSignature(r, r.URL.Query(), httpDate, "", "secret").String())
	} else {
		r.Header.Set(queryXAmzDate, date)
		r.Header.Set(headerXAmzContentSha256, unsignedPayload)
		headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
		signed := "host;x-amz-content-sha256;x-amz-date"
		if token != "" {
			headers = append(headers, "x-amz-security-token")
			signed += ";x-amz-security-token"
		}
		sig := calculateSignatureV4(signatureV4Data{dateTime: date, scope: sc, digest: v4.canonicalRequestHash(r, nil, headers, unsignedPayload)}, "secret")
		r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+credential+",SignedHeaders="+signed+",Signature="+sig.String())
	}
	return r
}

func TestSessionTokenProviders(t *testing.T) {
	now := time.Date(2026, time.September, 23, 0, 0, 0, 0, time.UTC)
	for _, version := range []int{2, 4} {
		for _, mode := range []string{"header", "query", "POST"} {
			for _, combined := range []bool{false, true} {
				for _, token := range []string{"valid-token", "wrong-token", ""} {
					for _, aware := range []bool{false, true} {
						name := fmt.Sprintf("v%d/%s/combined=%t/token=%q/aware=%t", version, mode, combined, token, aware)
						t.Run(name, func(t *testing.T) {
							p := &sessionProvider{}
							var provider CredentialsProvider[string] = tokenlessProvider{}
							if aware {
								provider = p
							}
							r := sessionRequest(t, version, mode, token, now)
							v := NewV2V4(provider, V4Config{Region: "us-east-1", Service: "s3"})
							v.v2.now = func() time.Time { return now }
							v.v4.now = v.v2.now
							var vr VerifiedRequest[string]
							var err error
							switch {
							case combined:
								vr, err = v.Verify(r, "")
							case version == 2:
								vr, err = v.v2.Verify(r, "")
							default:
								vr, err = v.v4.Verify(r)
							}
							valid := aware && token == "valid-token" || !aware && token == ""
							if !valid {
								if !errors.Is(err, ErrInvalidToken) {
									t.Fatalf("got %v, want ErrInvalidToken", err)
								}
							} else {
								if err != nil {
									t.Fatal(err)
								}
								want := "user"
								if aware {
									want = "session-user"
								}
								if vr.AuthData() != want {
									t.Fatalf("auth data %q, want %q", vr.AuthData(), want)
								}
							}
							if aware && p.calls != 1 {
								t.Fatalf("token-aware provider called %d times", p.calls)
							}
						})
					}
				}
			}
		}
	}
}

func TestRejectDuplicateSessionTokens(t *testing.T) {
	now := time.Date(2026, time.September, 23, 0, 0, 0, 0, time.UTC)
	for _, version := range []int{2, 4} {
		for _, mode := range []string{"header", "query", "POST"} {
			for _, combined := range []bool{false, true} {
				for _, extra := range []string{"valid-token", "wrong-token", ""} {
					t.Run(fmt.Sprintf("v%d/%s/combined=%t/extra=%q", version, mode, combined, extra), func(t *testing.T) {
						p := &sessionProvider{}
						r := sessionRequest(t, version, mode, "valid-token", now, extra)
						v := NewV2V4(p, V4Config{Region: "us-east-1", Service: "s3"})
						v.v2.now = func() time.Time { return now }
						v.v4.now = v.v2.now
						var err error
						switch {
						case combined:
							_, err = v.Verify(r, "")
						case version == 2:
							_, err = v.v2.Verify(r, "")
						default:
							_, err = v.v4.Verify(r)
						}
						if !errors.Is(err, ErrInvalidToken) {
							t.Fatalf("got %v, want ErrInvalidToken", err)
						}
						if p.calls != 0 {
							t.Fatalf("ambiguous tokens reached provider: %d calls", p.calls)
						}
					})
				}
			}
		}
	}
}

func TestV4RejectsUnsignedTokenHeader(t *testing.T) {
	now := time.Date(2026, time.September, 23, 0, 0, 0, 0, time.UTC)
	for _, mode := range []string{"header", "query"} {
		for _, combined := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/combined=%t", mode, combined), func(t *testing.T) {
				// Start with a valid tokenless signature, then attach a valid but unsigned
				// token. Rejection must happen before asking the provider about the token.
				r := sessionRequest(t, 4, mode, "", now)
				r.Header.Set(queryXAmzSecurityToken, "valid-token")
				p := &sessionProvider{}
				v := NewV2V4(p, V4Config{Region: "us-east-1", Service: "s3"})
				v.v4.now = func() time.Time { return now }
				var err error
				if combined {
					_, err = v.Verify(r, "")
				} else {
					_, err = v.v4.Verify(r)
				}
				if !errors.Is(err, ErrUnsignedHeader) {
					t.Fatalf("got %v, want ErrUnsignedHeader", err)
				}
				if p.calls != 0 {
					t.Fatalf("unsigned token reached provider: %d calls", p.calls)
				}
			})
		}
	}
}

func TestV4PresignedTokenKeyCase(t *testing.T) {
	now := time.Date(2026, time.September, 23, 0, 0, 0, 0, time.UTC)
	for _, combined := range []bool{false, true} {
		for _, aware := range []bool{false, true} {
			t.Run(fmt.Sprintf("combined=%t/aware=%t", combined, aware), func(t *testing.T) {
				r := sessionRequest(t, 4, "query", "", now)
				q := r.URL.Query()
				q.Del(queryXAmzSignature)
				q.Set("x-amz-security-token", "valid-token")
				p := &sessionProvider{}
				var provider CredentialsProvider[string] = tokenlessProvider{}
				if aware {
					provider = p
				}
				v := NewV2V4(provider, V4Config{Region: "us-east-1", Service: "s3"})
				v.v4.now = func() time.Time { return now }
				sig := calculateSignatureV4(signatureV4Data{
					dateTime: now.Format(timeFormatISO8601),
					scope:    scope{date: "20260923", region: "us-east-1", service: "s3"},
					digest:   v.v4.canonicalRequestHash(r, q, []string{"host"}, unsignedPayload),
				}, "secret")
				q.Set(queryXAmzSignature, sig.String())
				r.URL.RawQuery = q.Encode()
				var err error
				if combined {
					_, err = v.Verify(r, "")
				} else {
					_, err = v.v4.Verify(r)
				}
				// A token-aware provider sees an empty token and rejects it. A legacy
				// provider treats the lowercase key as ordinary query data and succeeds.
				if aware {
					if !errors.Is(err, ErrInvalidToken) || p.calls != 1 {
						t.Fatalf("got %v with %d provider calls", err, p.calls)
					}
				} else if err != nil {
					t.Fatalf("ordinary signed query data rejected: %v", err)
				}
			})
		}
	}
}

func TestV4PresignedValidatesQueryToken(t *testing.T) {
	now := time.Date(2026, time.September, 23, 0, 0, 0, 0, time.UTC)
	for _, combined := range []bool{false, true} {
		t.Run(fmt.Sprintf("combined=%t", combined), func(t *testing.T) {
			p := &sessionProvider{}
			v := NewV2V4(p, V4Config{Region: "us-east-1", Service: "s3"})
			v.v4.now = func() time.Time { return now }
			r := sessionRequest(t, 4, "query", "valid-token", now)
			// Sign a different token header: it is authenticated data, but only the
			// query token should be passed to the provider for session validation.
			r.Header.Set(queryXAmzSecurityToken, "not-a-valid-session-token")
			q := r.URL.Query()
			q.Del(queryXAmzSignature)
			q.Set(queryXAmzSignedHeaders, "host;x-amz-security-token")
			sig := calculateSignatureV4(signatureV4Data{
				dateTime: now.Format(timeFormatISO8601),
				scope:    scope{date: "20260923", region: "us-east-1", service: "s3"},
				digest:   v.v4.canonicalRequestHash(r, q, []string{"host", "x-amz-security-token"}, unsignedPayload),
			}, "secret")
			q.Set(queryXAmzSignature, sig.String())
			r.URL.RawQuery = q.Encode()
			var vr VerifiedRequest[string]
			var err error
			if combined {
				vr, err = v.Verify(r, "")
			} else {
				vr, err = v.v4.Verify(r)
			}
			if err != nil {
				t.Fatal(err)
			}
			if p.calls != 1 || vr.AuthData() != "session-user" {
				t.Fatalf("unexpected provider result: calls=%d data=%q", p.calls, vr.AuthData())
			}
			if got := r.Header.Get(queryXAmzSecurityToken); got != "not-a-valid-session-token" {
				t.Fatalf("token header was modified: %q", got)
			}
		})
	}
}

func TestV4HeaderAuthDoesNotUseQueryToken(t *testing.T) {
	now := time.Date(2026, time.September, 23, 0, 0, 0, 0, time.UTC)
	for _, combined := range []bool{false, true} {
		for _, aware := range []bool{false, true} {
			t.Run(fmt.Sprintf("combined=%t/aware=%t", combined, aware), func(t *testing.T) {
				p := &sessionProvider{}
				var provider CredentialsProvider[string] = tokenlessProvider{}
				if aware {
					provider = p
				}
				v := NewV2V4(provider, V4Config{Region: "us-east-1", Service: "s3"})
				v.v4.now = func() time.Time { return now }
				r := sessionRequest(t, 4, "header", "", now)
				q := url.Values{queryXAmzSecurityToken: {"valid-token"}}
				r.URL.RawQuery = q.Encode()
				date := now.Format(timeFormatISO8601)
				sc := scope{date: date[:8], region: "us-east-1", service: "s3"}
				signed := "host;x-amz-content-sha256;x-amz-date"
				sig := calculateSignatureV4(signatureV4Data{dateTime: date, scope: sc,
					digest: v.v4.canonicalRequestHash(r, q, []string{"host", "x-amz-content-sha256", "x-amz-date"}, unsignedPayload),
				}, "secret")
				r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=key/"+sc.String()+",SignedHeaders="+signed+",Signature="+sig.String())
				var err error
				if combined {
					_, err = v.Verify(r, "")
				} else {
					_, err = v.v4.Verify(r)
				}
				if aware {
					if !errors.Is(err, ErrInvalidToken) || p.calls != 1 || p.lastToken != "" {
						t.Fatalf("got %v, calls=%d, token=%q; want missing-token rejection", err, p.calls, p.lastToken)
					}
				} else if err != nil {
					t.Fatalf("valid tokenless header signature rejected: %v", err)
				}
			})
		}
	}
}
