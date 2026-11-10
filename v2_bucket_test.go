package awsig

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/zeebo/assert"
)

func TestV2BucketPath(t *testing.T) {
	p := simpleCredentialsProvider{accessKeyID: "key", secretAccessKey: "secret"}
	now := dummyNow(2026, time.September, 23, 0, 0, 0)
	for _, tc := range []struct{ path, bucket, canonical string }{
		{"/bucket", "", "/bucket/"},
		{"/bucket", "", "/bucket"},
		{"/bucket/", "", "/bucket/"},
		{"/bucket/key", "", "/bucket/key"},
		{"/", "", "/"},
		{"/", "bucket", "/bucket/"},
		{"/key", "bucket", "/bucket/key"},
	} {
		for _, presigned := range []bool{false, true} {
			for _, combined := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s signed as %s/bucket=%s/presigned=%t/combined=%t", tc.path, tc.canonical, tc.bucket, presigned, combined), func(t *testing.T) {
					v := NewV2V4(p, V4Config{})
					v.v2.now = now
					r := httptest.NewRequest("GET", "http://localhost"+tc.path, nil)
					date := now().UTC().Format(http.TimeFormat)
					if presigned {
						date = strconv.FormatInt(now().Add(time.Hour).Unix(), 10)
					}
					sig := calculateSignatureV2("GET\n\n\n"+date+"\n"+tc.canonical, "secret")
					if presigned {
						r.URL.RawQuery = url.Values{"AWSAccessKeyId": {"key"}, "Expires": {date}, "Signature": {sig.String()}}.Encode()
					} else {
						r.Header.Set("Date", date)
						r.Header.Set("Authorization", "AWS key:"+sig.String())
					}
					var err error
					if combined {
						_, err = v.Verify(r, tc.bucket)
					} else {
						_, err = v.v2.Verify(r, tc.bucket)
					}
					assert.NoError(t, err)
				})
			}
		}
	}
}

func TestV2PostMissingSignature(t *testing.T) {
	v2 := NewV2[exampleAuthData](simpleCredentialsProvider{accessKeyID: "key", secretAccessKey: "secret"})
	// PostForm canonicalizes its keys, so build it like the parser does.
	form := make(PostForm)
	form.Set(queryAWSAccessKeyId, PostFormElement{Value: "key"})
	form.Set(formNamePolicy, PostFormElement{Value: "e30="})
	_, err := v2.verifyPost(t.Context(), form)
	assert.That(t, errors.Is(err, ErrInvalidArgument))
}

func TestV2PostWithoutCredentials(t *testing.T) {
	// S3 answers an anonymous POST, with neither AWSAccessKeyId nor Signature, with AccessDenied, so
	// it isn't the missing-Signature InvalidArgument.
	v2 := NewV2[exampleAuthData](simpleCredentialsProvider{accessKeyID: "key", secretAccessKey: "secret"})
	form := make(PostForm)
	form.Set(formNamePolicy, PostFormElement{Value: "e30="})
	_, err := v2.verifyPost(t.Context(), form)
	assert.Error(t, err)
	assert.False(t, errors.Is(err, ErrInvalidArgument))
}
