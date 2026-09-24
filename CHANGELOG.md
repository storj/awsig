# Changelog

## Unreleased

### Compatibility

- SigV2 retains legacy path-style bucket-only canonicalization: requests sent
  to `/bucket` are signed as `/bucket/` for compatibility with existing clients.
  Object paths and virtual-hosted requests are unchanged.
- SigV2 signs decoded subresource and `response-*` query values. More
  subresources are included in signatures, including `tagging`, `retention`,
  `legal-hold`, `cors`, `restore`, `encryption`, and `object-lock`; changing these
  parameters now changes the expected signature.
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

