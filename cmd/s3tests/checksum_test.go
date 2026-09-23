package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func signChecksumRequest(r *http.Request, payloadHash string) {
	date := time.Now().UTC().Format("20060102T150405Z")
	r.Header.Set("X-Amz-Date", date)
	r.Header.Set("X-Amz-Content-Sha256", payloadHash)
	names := []string{"host"}
	for name := range r.Header {
		names = append(names, strings.ToLower(name))
	}
	sort.Strings(names)
	var headers strings.Builder
	for _, name := range names {
		value := strings.Join(r.Header.Values(name), ",")
		if name == "host" {
			value = r.Host
		}
		fmt.Fprintf(&headers, "%s:%s\n", name, value)
	}
	signed := strings.Join(names, ";")
	canonical := r.Method + "\n" + r.URL.EscapedPath() + "\n" + r.URL.Query().Encode() + "\n" + headers.String() + "\n" + signed + "\n" + payloadHash
	mac := func(k []byte, s string) []byte { h := hmac.New(sha256.New, k); h.Write([]byte(s)); return h.Sum(nil) }
	scope := date[:8] + "/us-east-1/s3/aws4_request"
	key := mac(mac(mac(mac([]byte("AWS4secret"), date[:8]), "us-east-1"), "s3"), "aws4_request")
	signature := mac(key, "AWS4-HMAC-SHA256\n"+date+"\n"+scope+"\n"+fmt.Sprintf("%x", sha256.Sum256([]byte(canonical))))
	r.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=key/%s,SignedHeaders=%s,Signature=%x", scope, signed, signature))
}

func TestDeleteObjectsFlexibleChecksums(t *testing.T) {
	for _, algorithm := range []struct {
		name    string
		newHash func() hash.Hash
	}{
		{"CRC32", func() hash.Hash { return crc32.NewIEEE() }},
		{"CRC32C", func() hash.Hash { return crc32.New(crc32.MakeTable(crc32.Castagnoli)) }},
		{"CRC64NVME", func() hash.Hash { return crc64.New(crc64.MakeTable(0x9a6c9329ac4bc9b5)) }},
		{"SHA1", sha1.New}, {"SHA256", sha256.New},
	} {
		for _, trailing := range []bool{false, true} {
			for _, valid := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/trailing=%t/valid=%t", algorithm.name, trailing, valid), func(t *testing.T) {
					log := slog.New(slog.NewTextHandler(io.Discard, nil))
					svc := newServer(log, &credentialsDB{log: log, entries: map[string]credentialsData{"key": {accessKeyID: "key", secretAccessKey: "secret"}}})
					svc.data["bucket"] = bucket{name: "bucket", objects: []object{{name: "victim"}}}
					payload := "<Delete><Object><Key>victim</Key></Object><Quiet>true</Quiet></Delete>"
					h := algorithm.newHash()
					if valid {
						h.Write([]byte(payload))
					} else {
						h.Write([]byte("different"))
					}
					checksum := base64.StdEncoding.EncodeToString(h.Sum(nil))
					header := "x-amz-checksum-" + strings.ToLower(algorithm.name)
					body, payloadHash := payload, "UNSIGNED-PAYLOAD"
					if trailing {
						body = fmt.Sprintf("%x\r\n%s\r\n0\r\n%s:%s\r\n\r\n", len(payload), payload, header, checksum)
						payloadHash = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
					}
					r := httptest.NewRequest("POST", "http://localhost/bucket?delete", strings.NewReader(body))
					r.Header.Set("x-amz-sdk-checksum-algorithm", algorithm.name)
					if trailing {
						r.Header.Set("x-amz-trailer", header)
						r.Header.Set("Content-Encoding", "aws-chunked")
						r.Header.Set("x-amz-decoded-content-length", strconv.Itoa(len(payload)))
					} else {
						r.Header.Set(header, checksum)
					}
					signChecksumRequest(r, payloadHash)
					rr := httptest.NewRecorder()
					svc.ServeHTTP(rr, r)
					if valid {
						if rr.Code != http.StatusOK || len(svc.data["bucket"].objects) != 0 {
							t.Fatalf("valid deletion failed: %d %s", rr.Code, rr.Body.String())
						}
					} else if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "<Code>BadDigest</Code>") || len(svc.data["bucket"].objects) != 1 {
						t.Fatalf("corrupt deletion not rejected: %d %s", rr.Code, rr.Body.String())
					}
				})
			}
		}
	}
}

func TestRequestChecksumDeclarations(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers http.Header
	}{
		{"unknown algorithm", http.Header{"X-Amz-Sdk-Checksum-Algorithm": {"unknown"}}},
		{"empty algorithm", http.Header{"X-Amz-Sdk-Checksum-Algorithm": {""}}},
		{"missing sha256", http.Header{"X-Amz-Sdk-Checksum-Algorithm": {"SHA256"}}},
		{"duplicate algorithm", http.Header{"X-Amz-Sdk-Checksum-Algorithm": {"CRC32", "SHA256"}}},
		{"unknown trailer", http.Header{"X-Amz-Trailer": {"x-amz-unknown"}}},
		{"multiple trailers", http.Header{"X-Amz-Trailer": {"x-amz-checksum-crc32,x-amz-checksum-sha1"}}},
		{"empty trailer", http.Header{"X-Amz-Trailer": {""}}},
		{"duplicate trailer", http.Header{"X-Amz-Trailer": {"x-amz-checksum-crc32", "x-amz-checksum-crc32"}}},
		{"inline and trailing", http.Header{"X-Amz-Trailer": {"x-amz-checksum-crc32"}, "X-Amz-Checksum-Crc32": {"AAAAAA=="}}},
		{"mismatched algorithm", http.Header{"X-Amz-Sdk-Checksum-Algorithm": {"SHA256"}, "X-Amz-Trailer": {"x-amz-checksum-crc32"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			svc := &service{log: log}
			r := httptest.NewRequest("POST", "/bucket?delete", nil)
			r.Header = tc.headers
			r.Header.Set("Content-Encoding", "aws-chunked")
			r.Header.Set("X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
			rr := httptest.NewRecorder()
			if _, ok := svc.requestChecksums(rr, r); ok || rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "<Code>InvalidRequest</Code>") {
				t.Fatalf("invalid declaration accepted: %d %s", rr.Code, rr.Body.String())
			}
		})
	}
}
