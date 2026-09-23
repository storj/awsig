package main

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/amwolff/awsig"
)

func TestAWSigErrorResponses(t *testing.T) {
	for _, tc := range []struct {
		err    error
		code   string
		status int
	}{
		{awsig.ErrInvalidToken, "InvalidToken", 400},
		{awsig.ErrInvalidRequest, "InvalidRequest", 400},
		{awsig.ErrMessageTooLarge, "MaxPostPreDataLengthExceededError", 400},
		{errors.Join(awsig.ErrMalformedPOSTRequest, awsig.ErrMessageTooLarge), "MaxPostPreDataLengthExceededError", 400},
		{errors.New("unexpected failure"), "InternalError", 500},
	} {
		t.Run(tc.err.Error(), func(t *testing.T) {
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			rr := httptest.NewRecorder()
			awsigErrorToHTTPError(context.Background(), log, rr, fmt.Errorf("wrapped: %w", tc.err))
			var response struct{ Code string }
			if err := xml.Unmarshal(rr.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if rr.Code != tc.status || response.Code != tc.code {
				t.Fatalf("got %d %s, want %d %s", rr.Code, response.Code, tc.status, tc.code)
			}
		})
	}
}
