# Security Boundaries

## Authorization boundary

`Target.status == VERIFIED` with a non-expired `authorizationExpiresAt` is required to create and start an assessment. The worker checks the same condition again. Local/private targets require a system administrator to approve a hostname restricted to local/internal fixture conventions; this approval is explicit and sets the target-specific `allowPrivateNetwork` flag.

## Network boundary

Only HTTP and HTTPS are accepted. User information in URLs is rejected. Hostnames are normalized to ASCII and matched on an exact or dot-delimited subdomain boundary. Only target-authorized ports are accepted. DNS is resolved immediately before transport, every answer is classified, prohibited ranges are blocked, and the approved address is pinned into the socket lookup. Redirects are rechecked before following.

The scope client permits only GET, HEAD, and OPTIONS. It imposes time and response-size limits and removes sensitive request headers when following redirects. Scanner services must not instantiate general-purpose network clients.

## Tenant boundary

JWT authentication identifies a current active user. Workspace membership and role are loaded by the backend for each workspace route. Resource queries combine `workspaceId` with resource identifiers. Hiding frontend controls is not considered authorization.

## Evidence and model boundary

Target content is untrusted data. Evidence redaction removes credential-bearing headers and common secret/token patterns before persistence. Qwen has no network tool and will receive structured evidence through a private provider interface. An output without valid evidence references must be rejected rather than converted into a finding.

## Current implementation boundary

Day 1 implements authorization, scope validation, durable scan orchestration entry, and the schema for later stages. Discovery and security analyzers are not yet consumers of their queued jobs and therefore are not represented as completed.
