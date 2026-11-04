# Security Boundaries

## Engagement and execution boundary

Business authorization must be recorded as an engagement grant referencing an encrypted preserved document and immutable scope/ROE revision. Queue admission and every worker HTTP transport recheck current organization/workspace membership, grant validity/revocation, engagement lifecycle, actual destination and limits. See [FOUNDATION.md](FOUNDATION.md) for the implemented boundary and release blockers. Domain ownership challenges are not a substitute for this permission record.

## Network boundary

Only HTTP and HTTPS are accepted. User information in URLs is rejected. Hostnames are normalized to ASCII and matched against configured allowed domains on an exact or dot-delimited subdomain boundary. Only configured ports are accepted. Excluded paths are blocked. DNS is resolved immediately before transport, every answer is classified, prohibited ranges are blocked unless the target explicitly permits private networking, and the approved address is pinned into the socket lookup. Redirects are rechecked before following.

Production worker policy currently permits only GET, HEAD, and OPTIONS, regardless of broader low-level transport capabilities. It imposes time and response-size limits and removes sensitive request headers when following redirects. Scanner services must not instantiate general-purpose network clients.

## Tenant boundary

JWT authentication identifies a current active user. Organization membership, workspace membership and role are loaded by the backend for each workspace route. Resource queries combine `workspaceId` with resource identifiers. Hiding frontend controls is not considered authorization.

## Evidence and model boundary

Target content is untrusted data. Evidence redaction removes credential-bearing headers and common secret/token patterns before persistence. Qwen has no network tool and will receive structured evidence through a private provider interface. An output without valid evidence references must be rejected rather than converted into a finding.

## Current implementation boundary

The complete worker pipeline consumes persisted jobs and uses the same target-derived scope policy for discovery, crawling, API discovery, fingerprinting, passive analysis, and safe active analysis. Model output cannot widen this boundary or invoke network operations.

Evidence and audit records are append-only at the database layer. Authorization originals are encrypted and bound to tenant context. Report downloads verify hashes and reject filesystem escapes. Secret pattern detection does not replace manual redaction or publication approval.
