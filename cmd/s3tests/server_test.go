package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDeleteObjectsVerifiesBody(t *testing.T) {
	for _, valid := range []bool{false, true} {
		t.Run(fmt.Sprint(valid), func(t *testing.T) {
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			svc := newServer(log, &credentialsDB{log: log, entries: map[string]credentialsData{"key": {accessKeyID: "key", secretAccessKey: "secret"}}})
			svc.data["bucket"] = bucket{name: "bucket", objects: []object{{name: "victim"}}}
			payload := "<Delete><Object><Key>victim</Key></Object><Quiet>true</Quiet></Delete>"
			r := httptest.NewRequest("POST", "http://localhost/bucket?delete", strings.NewReader(payload))
			r.SetPathValue("bucket", "bucket")
			digest := md5.Sum([]byte(payload))
			contentMD5 := base64.StdEncoding.EncodeToString(digest[:])
			r.Header.Set("Content-MD5", contentMD5)
			date := time.Now().UTC().Format("20060102T150405Z")
			day := date[:8]
			scope := day + "/us-east-1/s3/aws4_request"
			hash := fmt.Sprintf("%x", sha256.Sum256(nil))
			if valid {
				hash = fmt.Sprintf("%x", sha256.Sum256([]byte(payload)))
			}
			r.Header.Set("X-Amz-Date", date)
			r.Header.Set("X-Amz-Content-Sha256", hash)
			signed := "content-md5;host;x-amz-content-sha256;x-amz-date"
			canonical := "POST\n/bucket\ndelete=\ncontent-md5:" + contentMD5 + "\nhost:localhost\nx-amz-content-sha256:" + hash + "\nx-amz-date:" + date + "\n\n" + signed + "\n" + hash
			mac := func(k []byte, s string) []byte { h := hmac.New(sha256.New, k); h.Write([]byte(s)); return h.Sum(nil) }
			key := mac(mac(mac(mac([]byte("AWS4secret"), day), "us-east-1"), "s3"), "aws4_request")
			sig := mac(key, "AWS4-HMAC-SHA256\n"+date+"\n"+scope+"\n"+fmt.Sprintf("%x", sha256.Sum256([]byte(canonical))))
			r.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=key/%s,SignedHeaders=%s,Signature=%x", scope, signed, sig))
			rr := httptest.NewRecorder()
			svc.deleteObjects(rr, r)
			if valid {
				if rr.Code != http.StatusOK || len(svc.data["bucket"].objects) != 0 {
					t.Fatalf("valid deletion failed: %d %s", rr.Code, rr.Body.String())
				}
			} else {
				if rr.Code != http.StatusBadRequest || len(svc.data["bucket"].objects) != 1 {
					t.Fatalf("bad digest not rejected: %d %s", rr.Code, rr.Body.String())
				}
			}
		})
	}
}

func TestDeleteObjectsVerifiesMD5(t *testing.T) {
	for _, mode := range []string{"valid", "altered", "missing", "malformed", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			svc := newServer(log, &credentialsDB{log: log, entries: map[string]credentialsData{"key": {accessKeyID: "key", secretAccessKey: "secret"}}})
			svc.data["bucket"] = bucket{name: "bucket", objects: []object{{name: "victim"}}}
			payload := "<Delete><Object><Key>victim</Key></Object><Quiet>true</Quiet></Delete>"
			signedPayload := payload
			if mode == "altered" {
				signedPayload = strings.ReplaceAll(payload, "victim", "other")
			}
			digest := md5.Sum([]byte(signedPayload))
			encoded := base64.StdEncoding.EncodeToString(digest[:])
			switch mode {
			case "missing":
				encoded = ""
			case "malformed":
				encoded = "invalid"
			}
			date := time.Now().UTC().Format(http.TimeFormat)
			mac := hmac.New(sha1.New, []byte("secret"))
			mac.Write([]byte("POST\n" + encoded + "\n\n" + date + "\n/bucket/?delete"))
			r := httptest.NewRequest("POST", "http://localhost/bucket?delete", strings.NewReader(payload))
			if mode != "missing" {
				r.Header.Set("Content-MD5", encoded)
			}
			if mode == "duplicate" {
				r.Header.Add("Content-MD5", encoded)
			}
			r.Header.Set("Date", date)
			r.Header.Set("Authorization", "AWS key:"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
			rr := httptest.NewRecorder()
			svc.ServeHTTP(rr, r)
			if mode == "valid" {
				if rr.Code != http.StatusOK || len(svc.data["bucket"].objects) != 0 {
					t.Fatalf("valid deletion failed: %d %s", rr.Code, rr.Body.String())
				}
			} else {
				if rr.Code != http.StatusBadRequest || len(svc.data["bucket"].objects) != 1 {
					t.Fatalf("invalid deletion accepted: %d %s", rr.Code, rr.Body.String())
				}
				if mode == "altered" && !strings.Contains(rr.Body.String(), "BadDigest") {
					t.Fatalf("expected BadDigest: %s", rr.Body.String())
				}
			}
		})
	}
}

func TestDeleteObjectsVerifiesCRC32(t *testing.T) {
	for _, mode := range []string{"valid", "altered", "missing", "malformed", "duplicate", "both-valid", "both-bad-md5"} {
		t.Run(mode, func(t *testing.T) {
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			svc := newServer(log, &credentialsDB{log: log, entries: map[string]credentialsData{"key": {accessKeyID: "key", secretAccessKey: "secret"}}})
			svc.data["bucket"] = bucket{name: "bucket", objects: []object{{name: "victim"}}}
			payload := "<Delete><Object><Key>victim</Key></Object><Quiet>true</Quiet></Delete>"
			checksumPayload := payload
			if mode == "altered" {
				checksumPayload = strings.ReplaceAll(payload, "victim", "other")
			}
			h := crc32.NewIEEE()
			h.Write([]byte(checksumPayload))
			encoded := base64.StdEncoding.EncodeToString(h.Sum(nil))
			if mode == "malformed" {
				encoded = "invalid"
			}
			r := httptest.NewRequest("POST", "http://localhost/bucket?delete", strings.NewReader(payload))
			if mode != "missing" {
				r.Header.Set("X-Amz-Checksum-Crc32", encoded)
			}
			if mode == "duplicate" {
				r.Header.Add("X-Amz-Checksum-Crc32", encoded)
			}
			r.Header.Set("X-Amz-Sdk-Checksum-Algorithm", "CRC32")
			if strings.HasPrefix(mode, "both-") {
				md5Payload := payload
				if mode == "both-bad-md5" {
					md5Payload = "different"
				}
				digest := md5.Sum([]byte(md5Payload))
				r.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(digest[:]))
			}
			date := time.Now().UTC().Format(http.TimeFormat)
			canonical := "POST\n" + r.Header.Get("Content-MD5") + "\n\n" + date + "\n"
			if values := r.Header.Values("X-Amz-Checksum-Crc32"); len(values) > 0 {
				canonical += "x-amz-checksum-crc32:" + strings.Join(values, ",") + "\n"
			}
			canonical += "x-amz-sdk-checksum-algorithm:CRC32\n/bucket/?delete"
			mac := hmac.New(sha1.New, []byte("secret"))
			mac.Write([]byte(canonical))
			r.Header.Set("Date", date)
			r.Header.Set("Authorization", "AWS key:"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
			rr := httptest.NewRecorder()
			svc.ServeHTTP(rr, r)
			if mode == "valid" || mode == "both-valid" {
				if rr.Code != http.StatusOK || len(svc.data["bucket"].objects) != 0 {
					t.Fatalf("valid deletion failed: %d %s", rr.Code, rr.Body.String())
				}
			} else {
				if rr.Code != http.StatusBadRequest || len(svc.data["bucket"].objects) != 1 {
					t.Fatalf("invalid deletion accepted: %d %s", rr.Code, rr.Body.String())
				}
				if (mode == "altered" || mode == "both-bad-md5") && !strings.Contains(rr.Body.String(), "BadDigest") {
					t.Fatalf("expected BadDigest: %s", rr.Body.String())
				}
			}
		})
	}
}
