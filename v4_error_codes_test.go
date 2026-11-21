package awsig

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zeebo/assert"
)

func TestStreamingMinimumChunkIs8KiB(t *testing.T) {
	for _, tc := range []struct {
		first int
		want  error
	}{
		{8191, ErrInvalidChunkSize},
		{8192, nil},
	} {
		t.Run(fmt.Sprint(tc.first), func(t *testing.T) {
			body := fmt.Sprintf("%x\r\n%s\r\n1\r\nb\r\n0\r\n\r\n", tc.first, strings.Repeat("a", tc.first))
			vr, err := newV4VerifiedRequest(strings.NewReader(body), v4VerifiedData[struct{}]{options: parsedXAmzContentSHA256{
				unsigned:             true,
				streaming:            true,
				decodedContentLength: int64(tc.first + 1),
			}})
			assert.NoError(t, err)
			rd, err := vr.Reader()
			assert.NoError(t, err)
			_, err = io.ReadAll(rd)
			assert.That(t, errors.Is(err, tc.want))
			if tc.want != nil {
				// It's what the reader returned before ErrInvalidChunkSize.
				assert.That(t, errors.Is(err, ErrEntityTooSmall))
			}
		})
	}
}

func TestV4UnsignedHeaders(t *testing.T) {
	v := NewV4(simpleCredentialsProvider{accessKeyID: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}, V4Config{Region: "us-east-1", Service: "s3"})
	v.now = dummyNow(2013, time.May, 24, 0, 0, 0)
	for _, header := range []string{"x-amz-meta-foo", "Content-MD5"} {
		t.Run(header, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
			r.Header.Set("Range", "bytes=0-9")
			r.Header.Set("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
			r.Header.Set("x-amz-date", "20130524T000000Z")
			_, err := v.Verify(r)
			assert.NoError(t, err)
			r.Header.Set(header, "1B2M2Y8AsgTpgAmY7PhCfg==") // added after signing
			_, err = v.Verify(r)
			assert.That(t, errors.Is(err, ErrUnsignedHeader))
			// It's what the verifier returned before ErrUnsignedHeader.
			assert.That(t, errors.Is(err, ErrMissingSecurityHeader))
		})
	}
}

func TestV4PresignedMalformedAuthorization(t *testing.T) {
	v := NewV4(simpleCredentialsProvider{accessKeyID: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}, V4Config{Region: "us-east-1", Service: "s3"})
	v.now = dummyNow(2013, time.May, 24, 0, 0, 0)
	for _, tc := range []struct{ name, credential, signedHeaders string }{
		{"credential", "garbage", "host"},
		{"credential date", "AKIAIOSFODNN7EXAMPLE%2F20130523%2Fus-east-1%2Fs3%2Faws4_request", "host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential="+tc.credential+
				"&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders="+tc.signedHeaders+"&X-Amz-Signature="+strings.Repeat("0", 64), nil)
			_, err := v.Verify(r)
			assert.That(t, errors.Is(err, ErrAuthorizationQueryParametersError))
			// It's what the verifier returned before ErrAuthorizationQueryParametersError.
			assert.That(t, errors.Is(err, ErrAuthorizationHeaderMalformed))
		})
	}
}

// TestV4SignedTransferEncoding checks a request that signs Transfer-Encoding, like the AWS CLI v1
// sending an aws-chunked body with a trailer, as Go's HTTP server parses it: with the header moved
// to r.TransferEncoding.
func TestV4SignedTransferEncoding(t *testing.T) {
	const (
		accessKeyID     = "AKIAIOSFODNN7EXAMPLE"
		secretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		dateTime        = "20130524T000000Z"
		scope           = "20130524/us-east-1/s3/aws4_request"
		signedHeaders   = "host;transfer-encoding;x-amz-content-sha256;x-amz-date"
	)
	canonicalRequest := "PUT\n/bucket/key\n\n" +
		"host:example.com\ntransfer-encoding:chunked\nx-amz-content-sha256:UNSIGNED-PAYLOAD\nx-amz-date:" + dateTime + "\n\n" +
		signedHeaders + "\nUNSIGNED-PAYLOAD"
	digest := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := "AWS4-HMAC-SHA256\n" + dateTime + "\n" + scope + "\n" + hex.EncodeToString(digest[:])
	key := []byte("AWS4" + secretAccessKey)
	for _, part := range []string{"20130524", "us-east-1", "s3", "aws4_request", stringToSign} {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(part))
		key = mac.Sum(nil)
	}

	raw := "PUT /bucket/key HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n" +
		"X-Amz-Content-Sha256: UNSIGNED-PAYLOAD\r\nX-Amz-Date: " + dateTime + "\r\n" +
		"Authorization: AWS4-HMAC-SHA256 Credential=" + accessKeyID + "/" + scope + ",SignedHeaders=" + signedHeaders + ",Signature=" + hex.EncodeToString(key) + "\r\n" +
		"\r\n5\r\nhello\r\n0\r\n\r\n"
	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	assert.NoError(t, err)
	assert.Equal(t, "", r.Header.Get("Transfer-Encoding"))

	v := NewV4(simpleCredentialsProvider{accessKeyID: accessKeyID, secretAccessKey: secretAccessKey}, V4Config{Region: "us-east-1", Service: "s3"})
	v.now = dummyNow(2013, time.May, 24, 0, 0, 0)
	vr, err := v.Verify(r)
	assert.NoError(t, err)
	rd, err := vr.Reader()
	assert.NoError(t, err)
	body, err := io.ReadAll(rd)
	assert.NoError(t, err)
	assert.Equal(t, "hello", string(body))
	// The request's own headers are left alone.
	assert.Equal(t, "", r.Header.Get("Transfer-Encoding"))
}
