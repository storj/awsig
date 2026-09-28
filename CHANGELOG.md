# Changelog

## Unreleased

### Compatibility

- SigV2 retains legacy path-style bucket-only canonicalization: requests sent
  to `/bucket` are signed as `/bucket/` for compatibility with existing clients.
  Object paths and virtual-hosted requests are unchanged.
- SigV2 signs decoded subresource and `response-*` query values using the
  botocore 1.40.0 subresource list, including `storageClass`, `defaultObjectAcl`,
  `tagging`, `cors`, `restore`, and `object-lock`. Known operation selectors
  excluded by that list (`encryption`, `legal-hold`, `retention`,
  `intelligent-tiering`, `ownershipControls`, `policyStatus`, and
  `publicAccessBlock`) are rejected with `ErrInvalidRequest`; use SigV4 for them.
- SigV4 S3 canonicalization preserves the escaped path exactly as sent, including
  encoded slashes and the case of percent escapes, instead of decoding and
  re-encoding it. Non-S3 services apply another URI-encoding pass to the escaped
  path, including encoding existing percent escapes again. Non-S3 support is
  partial: paths are not normalized to remove dot segments or repeated slashes.
- SigV4 joins multiple values of a signed header into one `name:v1,v2` line
  instead of emitting one line per value, and collapses repeated ASCII spaces
  within values. SigV2 trims surrounding whitespace from each `x-amz-*` header
  value before joining values.
- SigV4 query canonicalization sorts encoded keys and values and correctly
  separates repeated query parameters. SigV2 also correctly separates repeated
  signed query parameters.
- SigV4 presigned and multipart POST requests dated up to `maxRequestTimeSkew`
  (15 minutes) in the future are accepted. Presigned expiration checks still
  apply, and applications remain responsible for POST policy expiration and
  conditions. SigV4 dates parsed from the HTTP `Date` header are normalized to UTC.
- Multipart parsing errors retain their underlying causes. The former internal
  `errMessageTooLarge` is exported as `ErrMessageTooLarge`, allowing callers to
  identify oversized form metadata with `errors.Is`. The multipart `file` field
  name is now matched case-insensitively.
- Malformed query strings fail with `ErrInvalidRequest` before authentication or
  multipart parsing in all public verifiers, rather than authenticating a
  partially parsed query.
- SigV4 streaming readers reject malformed or incomplete framing and invalid
  lengths, support small read buffers, and retain verification errors on
  subsequent reads. Checksum setup can be retried after an unsuccessful `Reader`
  call; checksum values must have the correct decoded length.
- SigV4 requires `X-Amz-Trailer` exactly when `X-Amz-Content-Sha256` names a
  `*-TRAILER` payload, and uses the algorithm it names as the trailing checksum,
  so callers no longer need to request one. A missing header, or a trailer that
  does not match it or is truncated, fails with the new `ErrMalformedTrailer`;
  truncated trailers also match `io.ErrUnexpectedEOF`. An unsupported or
  unexpected header, including any `X-Amz-Trailer` on a presigned request, fails
  with `ErrInvalidRequest`. Trailer names are matched case-insensitively. Checksum requests inconsistent with the payload (a trailing
  request without a trailer, a second trailing request, or one naming a
  different algorithm than `X-Amz-Trailer`) fail with the new
  `ErrInvalidChecksumRequest`. Requesting the same algorithm twice with the same
  value, such as Content-MD5 together with `X-Amz-Checksum-Md5`, is allowed;
  conflicting values fail with `ErrBadDigest`.

### Test server

- Malformed checksum trailers return HTTP 400 with `MalformedTrailerError`.
  Invalid requests and checksum requests return HTTP 400 with `InvalidRequest`.
