# Engagement Authorization and Target Scope

Authorization to assess a target is established through the organization's business and security engagement process before the target is entered into the platform. The platform does not attempt to prove domain ownership and does not use DNS TXT challenges, well-known files, email verification, or verification tokens.

## Target lifecycle

```text
CREATE TARGET -> CONFIGURE SCOPE -> READY -> START SCAN
```

A target without a valid scope remains `DRAFT`. Saving a valid scope moves it to `READY`. During execution it is `SCANNING`; terminal target states are `COMPLETED`, `FAILED`, or `CANCELLED`. `DISABLED` targets cannot be scanned.

The saved scope contains:

- one or more exact allowed domains, including the target origin hostname;
- whether dot-delimited subdomains of those domains are allowed;
- allowed TCP ports, including the target origin's effective port;
- excluded absolute paths; and
- an explicit private-network allowance, disabled by default.

## Scan-start rule

The API starts a scan only when the target exists in the caller's workspace, is enabled and not already scanning, has a valid persisted scope, and the caller has a role permitted to run assessments. Target reservation and scan queueing occur atomically so concurrent starts cannot scan the same target simultaneously.

## Hard network boundary

Every outbound HTTP operation is routed through the scope engine immediately before transport. URL scheme, normalized hostname, effective port, path exclusions, resolved addresses, DNS pinning, and redirect destinations are checked. A redirect to another domain is blocked unless that domain is explicitly included in the persisted scope.

Removing technical ownership verification does not authorize unrestricted scanning and does not weaken SSRF, private-address, DNS-rebinding, redirect-escape, or hostname-confusion defenses.
