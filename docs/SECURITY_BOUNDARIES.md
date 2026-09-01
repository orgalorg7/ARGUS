# Security Boundaries

## Engagement and execution boundary

Business authorization is established outside the platform before target entry. The platform does not perform domain-ownership challenges. It does require a valid persisted target scope and sufficient workspace permission before scan creation/start. A target is atomically reserved as `SCANNING` when its scan is queued, and workers reject jobs whose target is not in that state.

## Network boundary

Only HTTP and HTTPS are accepted. User information in URLs is rejected. Hostnames are normalized to ASCII and matched against configured allowed domains on an exact or dot-delimited subdomain boundary. Only configured ports are accepted. Excluded paths are blocked. DNS is resolved immediately before transport, every answer is classified, prohibited ranges are blocked unless the target explicitly permits private networking, and the approved address is pinned into the socket lookup. Redirects are rechecked before following.

The scope client permits only GET, HEAD, and OPTIONS. It imposes time and response-size limits and removes sensitive request headers when following redirects. Scanner services must not instantiate general-purpose network clients.

## Tenant boundary

JWT authentication identifies a current active user. Workspace membership and role are loaded by the backend for each workspace route. Resource queries combine `workspaceId` with resource identifiers. Hiding frontend controls is not considered authorization.

## Evidence and model boundary

Target content is untrusted data. Evidence redaction removes credential-bearing headers and common secret/token patterns before persistence. Qwen has no network tool and will receive structured evidence through a private provider interface. An output without valid evidence references must be rejected rather than converted into a finding.

## Current implementation boundary

The complete worker pipeline consumes persisted jobs and uses the same target-derived scope policy for discovery, crawling, API discovery, fingerprinting, passive analysis, and safe active analysis. Model output cannot widen this boundary or invoke network operations.
