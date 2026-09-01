# Scanning Pipeline

## Persisted chain

```text
QUEUED
  -> VALIDATING_SCOPE
  -> DISCOVERY
  -> CRAWLING
  -> API_DISCOVERY
  -> FINGERPRINTING
  -> PASSIVE_ANALYSIS
       scan.http -> scan.tls -> scan.headers -> scan.cookies
  -> SAFE_ACTIVE_ANALYSIS
       scan.cors
  -> NORMALIZING
  -> CORRELATING
  -> AI_ANALYSIS
       -> AI_ANALYSIS_WAITING_FOR_PROVIDER when a configured provider is temporarily unavailable
       -> DEGRADED when no provider is configured or validated output fails
  -> GENERATING_SCAN_REPORT
  -> GENERATING_VULNERABILITY_REPORTS
  -> COMPLETED | COMPLETED_WITH_WARNINGS
```

Every transition is stored in PostgreSQL. Every queue entry has a persisted `ScanJob` with a unique idempotency key before BullMQ delivery. A recovery loop republishes `CREATED` jobs after Redis reconnects. Workers treat an already-advanced stage as an idempotent completion rather than repeating a completed stage.

## Discovery

Discovery performs bounded GET requests for the authorized origin, `robots.txt`, `sitemap.xml`, `security.txt`, `openapi.json`, and `swagger.json`. The same scope engine used by later crawling validates and pins every destination. Discovery responses are persisted as redacted evidence immediately, so a later worker failure does not erase collected observations.

## Crawling

The asynchronous crawler enforces the configured URL/request/depth budgets, per-target request rate, concurrency, response size, timeout, retries, and redirect limit. It extracts links, forms, script assets, inline public route strings, sitemap locations, and robots sitemap declarations.

Crawl-trap controls remove tracking and session parameters, sort query strings, cap query/path complexity, detect recursively repeated segments, cap pagination values, and limit variants of normalized date/number/identifier path shapes.

Every network operation uses `ScopedHttpClient`. Off-scope page references are recorded as blocked requests and are never fetched.

## Evidence persistence

Each received response becomes a canonical `ScannerObservation` with one or more `Evidence` rows. Authorization, Cookie, Set-Cookie, tokens, passwords, API keys, and related secret fields are redacted before persistence. Evidence hashes use deterministic key ordering and SHA-256.

## API discovery

API discovery operates only on already observed documents and metadata. It extracts HTML form actions/parameters, API-like links and inline routes, OpenAPI/Swagger operations and parameters, and observed GraphQL route locations. It does not issue GraphQL introspection or active API calls. Candidate endpoints pass the scope engine before persistence.

## Technology fingerprinting

Fingerprinting uses explicit public response headers, cookie names, HTML generator metadata, asset paths, and framework attributes. Versions are stored only when a response explicitly provides the version. Every technology record links to crawler evidence IDs.

## Deterministic analysis

Passive adapters emit the canonical scanner observation contract and operate on persisted crawler evidence. Implemented checks cover HTTP response profiles and disclosures, contextual security headers, cookie attributes, authentication surfaces, verbose errors, public source maps, and TLS session/certificate metadata. Missing optional headers are never assigned critical severity merely because they are absent.

The TLS adapter makes a new DNS-pinned HEAD request only for HTTPS targets. The scoped client captures the negotiated protocol, cipher, authorization state, and public certificate fields without weakening certificate verification.

The safe-active stage sends a foreign `Origin` using a bounded GET request to discovered in-scope URLs. It respects the scan rate and remaining global request budget, never sends credentials, and records the observed CORS response. Failures degrade the stage and remain visible instead of producing a vulnerability claim.

Scanner observations are idempotent by stable signature. Job retries reuse existing observations and evidence rather than creating duplicates.

## Finding normalization and correlation

The finding engine maps only recognized deterministic observation types and rejects any observation without persisted evidence. Inventory-only observations remain available for coverage but do not become vulnerabilities. Definitions provide contextual severity, confidence, CWE/OWASP mappings, impact language, remediation, and manual-verification requirements.

Correlation groups site-wide controls at the asset/category level and endpoint-specific behavior at the endpoint level. Cookie/header discriminators prevent unrelated observations from merging. Evidence and observation IDs are unioned, never discarded. Canonical findings, evidence links, occurrences, and history are persisted idempotently before any AI call.

## Qwen analysis

The AI worker submits each deterministic finding with only its redacted persisted evidence to a private vLLM-compatible provider. System policy, assessment context, evidence provenance, and target-controlled data occupy explicitly separate prompt sections. The response must pass a strict schema and every cited evidence ID must be part of the input. One constrained correction retry is allowed.

Temporary outages of a configured provider move the stage into a persisted waiting state and retain the queue job for recovery. An absent provider or invalid per-finding output degrades AI analysis without deleting deterministic findings and advances to report generation.

## Reports and cancellation

The report worker refuses findings without linked evidence, writes files atomically, hashes generated HTML, and serves files only through authenticated workspace-scoped APIs. Cancellation requests are persisted and audited. Network stages poll the cancellation marker; normalization, correlation, AI, and per-finding reporting stop at safe boundaries.
