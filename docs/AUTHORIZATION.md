# Target Authorization

## Methods

- `DNS_TXT`: publish `aasp-verification=<token>` at `_security-assessment.<hostname>`.
- `WELL_KNOWN`: serve the exact token as plain text at `/.well-known/security-assessment-verification`.
- `MANUAL_ADMIN`: a system administrator may approve only a local/internal fixture hostname. This path is intended for owned demo fixtures and records the approving user.

The registration response displays the random token once. Only its SHA-256 digest and a short non-secret hint are persisted. Challenges expire after 24 hours. Successful target authorization expires after 30 days and must be renewed before another assessment starts.

## Enforcement points

1. Target registration creates `PENDING_VERIFICATION` state.
2. Verification validates the selected proof and stores its attempt/audit record.
3. Scan creation requires current `VERIFIED` authorization.
4. Scan start rechecks authorization.
5. Worker execution rechecks authorization.
6. Every outbound URL is checked by the scope engine immediately before its socket is opened.

Verification itself is narrowly bounded: DNS and well-known verification operate only against the exact registered public hostname and cannot follow redirects. Private/loopback targets cannot use these network verification paths.
