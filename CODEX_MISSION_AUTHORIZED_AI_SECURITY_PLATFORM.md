# CODEX MISSION — AUTHORIZED AI SECURITY ASSESSMENT PLATFORM

> **This file is the primary implementation contract for Codex.**
>
> Read this file completely before modifying the repository.
>
> Do not treat it as documentation-only.
>
> Treat it as the authoritative engineering specification, delivery plan, acceptance criteria, architecture contract, and execution policy for this repository.

---

# 0. MISSION

Build a working, production-oriented MVP of an:

# **AUTHORIZED AI SECURITY ASSESSMENT PLATFORM**

The platform accepts an explicitly authorized web application URL, performs a controlled and non-destructive security assessment, collects reproducible evidence, normalizes findings, uses a self-hosted open-weight Qwen 27B model for structured analysis, and generates:

1. A complete scan report.
2. A dedicated detailed report for every identified vulnerability/finding.

This is not a chatbot.

This is not a scanner wrapper with a pretty UI.

This is not a fake demo.

This is not a collection of hardcoded findings.

This must become a real end-to-end security assessment pipeline.

---

# 1. FINAL USER EXPERIENCE

The final flow must be:

```text
USER
  |
  v
LOGIN
  |
  v
WORKSPACE
  |
  v
REGISTER TARGET
  |
  v
CONFIGURE AUTHORIZED SCOPE
  |
  v
ENTER AUTHORIZED URL
  |
  v
START SECURITY ASSESSMENT
  |
  +--> Scope validation
  +--> DNS validation
  +--> Attack-surface discovery
  +--> Crawler
  +--> Endpoint discovery
  +--> API discovery
  +--> Technology fingerprinting
  +--> HTTP analysis
  +--> TLS analysis
  +--> Cookie analysis
  +--> Header analysis
  +--> CORS analysis
  +--> Authentication-surface analysis
  +--> Safe configuration checks
  +--> Controlled non-destructive active checks
  +--> Evidence collection
  +--> Observation normalization
  +--> Finding correlation
  +--> Deduplication
  +--> Severity/confidence scoring
  +--> Qwen 27B analysis
  +--> False-positive analysis
  +--> CWE/OWASP mapping
  +--> Remediation generation
  +--> Executive risk analysis
  |
  v
SCAN REPORT
  |
  +--> Vulnerability Report #1
  +--> Vulnerability Report #2
  +--> Vulnerability Report #3
  +--> ...
```

A scan is not considered complete until reports exist and every important finding is linked to evidence.

---

# 2. DELIVERY DEADLINE

The project must be structured around a **7-day MVP delivery**.

Do not spend the week designing abstractions that do not contribute to the final vertical slice.

Priority order:

```text
1. Engagement Authorization + Scope Safety
2. Real Scan Pipeline
3. Evidence Integrity
4. Finding Normalization
5. Qwen Integration
6. Reports
7. Recovery / Reliability
8. Dashboard Polish
9. Fine-tuning Improvements
```

If time becomes constrained:

```text
WORKING END-TO-END SYSTEM
>
EXTRA FEATURES
```

Never sacrifice authorization, evidence integrity, or scan correctness to add cosmetic features.

---

# 3. NON-NEGOTIABLE AUTHORIZATION AND SCOPE POLICY

The platform must only assess targets authorized through the organization's existing business/security engagement process before target entry. The platform does not re-prove technical ownership and must not require DNS TXT challenges, well-known files, verification tokens, email verification, or domain ownership challenges.

The platform's architectural responsibility is enforcement of the configured assessment scope.

Target states:

```text
DRAFT
READY
SCANNING
COMPLETED
FAILED
CANCELLED
DISABLED
```

The required flow is:

```text
CREATE TARGET -> CONFIGURE SCOPE -> READY -> START SCAN
```

An active assessment may begin when the target exists, is enabled, has valid persisted scope configuration, and the user has permission to start scans. No technical ownership-verification record belongs in the execution path.

Every outbound request must pass the scope engine. Do not validate scope only when the scan starts.

Required invariant:

```ts
await scopeEngine.assertAllowed(url);
```

must conceptually occur before every outbound request.

---

# 4. PROHIBITED BEHAVIOR

Do not implement or automate:

- malware deployment
- persistence
- ransomware behavior
- destructive exploitation
- remote shell deployment
- credential stuffing
- password cracking
- denial-of-service
- resource exhaustion
- destructive SQL manipulation
- destructive command execution
- data deletion
- unauthorized data extraction
- lateral movement
- pivoting to unrelated infrastructure
- bypassing configured scope
- aggressive exploitation of discovered vulnerabilities

If evidence indicates a vulnerability but confirming it would require risky/destructive behavior:

```text
manual_verification_required = true
```

and classify the result as requiring authorized manual verification.

The system may perform controlled, low-impact, non-destructive security validation.

---

# 5. MODEL REQUIREMENT

The primary reasoning model is a self-hosted open-weight Qwen 27B-class model.

Default target:

```text
Qwen/Qwen3.8-27B
```

Do not silently replace it with a proprietary model.

Do not make the core product depend on:

- OpenAI API
- Anthropic API
- Gemini API
- other proprietary hosted LLMs

The model layer must be abstracted so another compatible self-hosted model can be introduced later.

Supported serving modes should include:

- Hugging Face Transformers for experimentation
- vLLM-compatible production serving
- quantized inference where supported

---

# 6. IMPORTANT: THE DEVELOPER LAPTOP IS WEAK

Assume the developer laptop cannot run Qwen locally.

The laptop is only:

```text
Git
VS Code
SSH
Browser
```

Never require local GPU.

Never require local model weights.

Never require local training datasets.

Never commit model weights into Git.

The expected architecture is:

```text
WEAK LAPTOP
     |
     +--> Git repository
     |
     +--> Browser
     |
     +--> SSH
             |
             +----------------------+
             |                      |
             v                      v
       GOOGLE COLAB            CLOUD/VPS
       AI experiments          Platform services
       Qwen runtime            Scanner workers
       checkpoints             Database
       temporary API           Redis
```

---

# 7. COLAB IS THE QWEN RUNTIME

Google Colab must be supported as an **ephemeral Qwen inference worker**.

The platform must NOT assume the Colab runtime stays online forever.

Design for:

```text
COLAB STARTS
    |
    v
QWEN LOADS
    |
    v
PRIVATE INFERENCE API AVAILABLE
    |
    v
AI JOBS RUN
    |
    v
COLAB MAY DISCONNECT
```

If Colab disconnects:

- scanner jobs must remain safe
- deterministic evidence must remain persisted
- pending AI jobs must remain queued
- the scan must not be destroyed
- a new Qwen endpoint may be registered
- AI analysis must be resumable

The platform must treat model availability as recoverable infrastructure.

---

# 8. COLAB NOTEBOOK CONTRACT

Create these notebooks:

```text
notebooks/
├── 00_environment_gpu_check.ipynb
├── 01_security_dataset_ingestion.ipynb
├── 02_dataset_cleaning.ipynb
├── 03_qwen27b_baseline.ipynb
├── 04_qwen27b_qlora_prepare.ipynb
├── 05_qwen27b_qlora_train.ipynb
├── 06_qwen27b_posttrain_eval.ipynb
├── 07_qwen27b_quantization.ipynb
├── 08_qwen27b_inference_api.ipynb
├── 09_finding_reasoning_pipeline.ipynb
├── 10_security_report_generation.ipynb
└── 11_end_to_end_authorized_demo.ipynb
```

Every notebook must:

- run top-to-bottom
- print meaningful progress
- detect GPU
- detect VRAM
- inspect RAM/disk
- optionally mount Google Drive
- save expensive artifacts/checkpoints
- resume where practical
- validate outputs
- fail loudly when requirements are missing
- avoid hidden manual steps
- avoid storing secrets in source code

---

# 9. NOTEBOOK 00 — HARDWARE AND ENVIRONMENT

`00_environment_gpu_check.ipynb`

Detect and record:

- Python
- CUDA
- GPU name
- GPU count
- VRAM
- system RAM
- disk
- Drive
- PyTorch
- Transformers
- Accelerate
- PEFT
- TRL
- bitsandbytes

Generate:

```text
artifacts/environment_report.json
artifacts/model_compatibility_report.json
```

Before attempting Qwen loading, estimate whether the selected configuration is realistic.

Do not blindly attempt to load a large model and crash the runtime.

---

# 10. NOTEBOOK 01 — DATA INGESTION

`01_security_dataset_ingestion.ipynb`

Build a defensive security reasoning dataset from approved/public/local sources.

Allowed training/evaluation content includes:

- CWE descriptions
- OWASP guidance
- CVE metadata
- vulnerability descriptions
- defensive remediation guidance
- scanner observations
- security configuration examples
- HTTP/TLS/header/cookie/CORS observations
- professional security report examples

Normalize records into a canonical format:

```json
{
  "sample_id": "",
  "task_type": "",
  "evidence": {},
  "expected": {
    "classification": "",
    "severity": "",
    "confidence": 0.0,
    "cwe": [],
    "owasp": [],
    "explanation": "",
    "remediation": ""
  }
}
```

Output:

```text
datasets/processed/security_dataset.jsonl
```

---

# 11. NOTEBOOK 02 — DATA QUALITY

`02_dataset_cleaning.ipynb`

Detect:

- exact duplicates
- near duplicates
- malformed JSON
- missing evidence
- invalid severity
- suspicious label imbalance
- empty samples
- train/test overlap
- extremely long examples
- inconsistent CWE/OWASP labels

Generate:

```text
evaluations/dataset_quality_report.json
evaluations/dataset_quality_report.csv
```

Never invent metrics.

---

# 12. NOTEBOOK 03 — BASELINE

`03_qwen27b_baseline.ipynb`

Benchmark the base Qwen model before fine-tuning.

Required evaluation areas:

- strict JSON compliance
- severity classification
- CWE mapping
- OWASP mapping
- duplicate finding classification
- likely false-positive reasoning
- evidence grounding
- remediation quality
- unsupported claim rate
- hallucination rate

Save every prediction.

Output:

```text
evaluations/baseline_results.json
evaluations/baseline_predictions.jsonl
```

Do not cherry-pick successful examples.

---

# 13. NOTEBOOKS 04/05 — QLORA

Fine-tuning is allowed but is NOT the primary acceptance dependency.

If the base model already performs well enough, the final system must still ship.

Create:

```text
04_qwen27b_qlora_prepare.ipynb
05_qwen27b_qlora_train.ipynb
```

Requirements:

- PEFT
- QLoRA where compatible
- gradient checkpointing
- gradient accumulation
- checkpoint resume
- Drive checkpoint storage
- configurable batch size
- configurable context length
- configurable LoRA rank
- loss logging

Use presets:

```text
LOW_MEMORY
STANDARD
HIGH_MEMORY
```

Never fabricate successful fine-tuning if Colab hardware is insufficient.

---

# 14. NOTEBOOK 06 — POST-TRAINING EVALUATION

Compare:

```text
BASE MODEL
vs
FINE-TUNED MODEL
```

Use the same held-out test set.

Generate:

```text
metric
base
fine_tuned
delta
winner
```

If the fine-tuned model is worse on important metrics:

DO NOT deploy it.

---

# 15. NOTEBOOK 07 — QUANTIZATION

Evaluate practical deployment variants.

Measure:

- artifact size
- VRAM requirement
- model load success
- inference latency
- tokens/sec
- JSON validity
- quality change

Document recommended profiles for available hardware.

Never claim an unsupported configuration works.

---

# 16. NOTEBOOK 08 — COLAB INFERENCE API

This notebook is critical.

`08_qwen27b_inference_api.ipynb`

It must:

1. detect Colab hardware
2. mount Drive optionally
3. install pinned dependencies
4. resolve model configuration
5. load/download Qwen on the Colab/cloud side
6. generate an API secret at runtime
7. start the model server
8. expose only the required inference interface
9. run a health check
10. run a structured JSON test
11. print connection metadata
12. save non-secret endpoint metadata when appropriate

Secrets must never be committed.

Example runtime environment variables:

```text
QWEN_BASE_URL
QWEN_API_KEY
QWEN_MODEL
```

The backend must support dynamically updating the current model endpoint without rebuilding the application.

---

# 17. EPHEMERAL MODEL PROVIDER

Implement a model provider registry.

Example database/config concept:

```text
ModelProvider
-------------
id
name
baseUrl
modelName
status
lastHeartbeat
createdAt
updatedAt
```

Do not persist raw API keys in plain text.

Provider statuses:

```text
ONLINE
OFFLINE
DEGRADED
UNKNOWN
```

The backend should health-check the configured provider.

If unavailable:

```text
AI_ANALYSIS_WAITING_FOR_PROVIDER
```

Do not discard findings.

---

# 18. QWEN INPUT RULE

Qwen is the reasoning engine.

It is NOT the unrestricted scanner.

Bad:

```text
Scan https://example.com and hack it.
```

Correct:

```json
{
  "target": {
    "host": "authorized-example.test"
  },
  "observation": {
    "type": "SECURITY_HEADERS",
    "endpoint": "/",
    "scanner": "header-analyzer"
  },
  "evidence": [
    {
      "id": "EVID-123",
      "observation": "..."
    }
  ]
}
```

The model must analyze existing evidence.

---

# 19. PROMPT-INJECTION DEFENSE

Everything obtained from the assessed target is UNTRUSTED DATA.

This includes:

- HTML
- JavaScript
- JSON
- XML
- API output
- headers
- cookies
- comments
- metadata
- error messages
- uploaded text

Separate:

```text
SYSTEM_POLICY
ASSESSMENT_CONTEXT
STRUCTURED_EVIDENCE
UNTRUSTED_TARGET_DATA
```

Target content must never be allowed to:

- modify scope
- change authorization
- add another target
- call unrestricted tools
- reveal secrets
- change configuration
- override system policy

---

# 20. REPOSITORY STRUCTURE

Target monorepo:

```text
/
├── apps/
│   ├── web/
│   ├── api/
│   └── worker/
│
├── services/
│   ├── scope-engine/
│   ├── crawler/
│   ├── discovery-engine/
│   ├── api-discovery/
│   ├── technology-fingerprinter/
│   ├── scanner-http/
│   ├── scanner-tls/
│   ├── scanner-headers/
│   ├── scanner-cookies/
│   ├── scanner-cors/
│   ├── scanner-auth-surface/
│   ├── scanner-misconfiguration/
│   ├── evidence-engine/
│   ├── finding-engine/
│   ├── correlation-engine/
│   ├── ai-engine/
│   └── report-engine/
│
├── packages/
│   ├── schemas/
│   ├── shared/
│   ├── security-core/
│   ├── logger/
│   └── sdk/
│
├── notebooks/
├── datasets/
├── models/
├── checkpoints/
├── evaluations/
├── reports/
├── fixtures/
├── scripts/
├── tests/
├── docker/
├── docs/
├── docker-compose.yml
└── docker-compose.gpu.yml
```

Adapt sensibly if the repository already has a strong architecture.

Do not rewrite working systems unnecessarily.

---

# 21. CORE STACK

Preferred:

```text
Frontend:
Next.js
TypeScript

Backend:
NestJS
TypeScript

Database:
PostgreSQL

ORM:
Prisma

Queue:
Redis
BullMQ

Crawler:
Node.js HTTP stack + optional Playwright worker

AI:
Qwen 27B
vLLM/compatible serving

Containers:
Docker
Docker Compose
```

---

# 22. DATABASE ENTITIES

Implement appropriate entities for:

```text
User
Workspace
WorkspaceMember
Role
Target
ScopeRule
Scan
ScanConfig
ScanStage
ScanJob
DiscoveredAsset
DiscoveredURL
DiscoveredEndpoint
DiscoveredParameter
Technology
ScannerObservation
Evidence
Finding
FindingEvidence
FindingOccurrence
FindingHistory
AIAnalysis
Report
AuditEvent
Worker
WorkerHeartbeat
ModelProvider
```

Every scan-related entity must be workspace scoped.

---

# 23. RBAC

Required roles:

```text
OWNER
ADMIN
ANALYST
VIEWER
```

Backend enforcement is mandatory.

Frontend hiding is not authorization.

Automated tests must verify access control.

---

# 24. MULTI-TENANT ISOLATION

A user in Workspace A must never retrieve or modify Workspace B:

- targets
- scans
- evidence
- findings
- reports
- model-provider settings when workspace-specific

Write tenant-isolation tests.

---

# 25. SCAN STATE MACHINE

Implement explicit states:

```text
CREATED
AUTHORIZED
QUEUED
VALIDATING_SCOPE
DISCOVERY
CRAWLING
API_DISCOVERY
FINGERPRINTING
PASSIVE_ANALYSIS
SAFE_ACTIVE_ANALYSIS
NORMALIZING
CORRELATING
AI_ANALYSIS
AI_ANALYSIS_WAITING_FOR_PROVIDER
GENERATING_SCAN_REPORT
GENERATING_VULNERABILITY_REPORTS
COMPLETED
COMPLETED_WITH_WARNINGS
FAILED
CANCELLED
```

Persist transitions.

Do not store progress only in memory.

---

# 26. SCAN PROFILES

Support:

```text
LIGHT
STANDARD
DEEP_SAFE
```

Configurable:

- max crawl depth
- maximum URLs
- maximum requests
- request timeout
- requests/second
- concurrency
- redirect behavior
- include authorized subdomains
- scan profile

All profiles remain non-destructive.

---

# 27. SCOPE ENGINE

The scope engine is security critical.

Validate:

- protocol
- hostname
- domain
- subdomain
- port
- resolved IP
- redirect destination

Block by default:

- localhost
- loopback
- private address ranges unless explicitly authorized
- link-local
- cloud metadata endpoints
- unexpected protocols

Protect against:

- SSRF
- DNS rebinding
- redirect escape
- hostname confusion
- scope bypass through redirects

Every outbound HTTP operation must pass scope checks.

---

# 28. CRAWLER

Build an asynchronous crawler with:

- canonical URL normalization
- deduplication
- crawl-depth control
- request budget
- URL budget
- rate limiting
- retries
- timeout
- content-type awareness
- redirect scope validation

Discover:

- pages
- links
- forms
- scripts
- query parameters
- API-like routes
- robots.txt
- sitemap.xml
- security.txt
- OpenAPI references
- Swagger references
- safely discoverable GraphQL metadata

Defend against:

- infinite pagination
- calendars
- recursive URL generators
- tracking parameter explosions
- session identifier explosions

---

# 29. OPTIONAL BROWSER WORKER

Use Playwright where it materially improves attack-surface discovery.

Collect:

- client-side routes
- XHR/fetch destinations
- scripts
- network requests
- form metadata

Do not allow target content to control privileged logic.

---

# 30. TECHNOLOGY FINGERPRINTING

Infer technologies from:

- HTTP headers
- cookies
- HTML
- JavaScript
- public asset signatures
- public metadata

Output:

```json
{
  "technology": "",
  "possibleVersion": "",
  "confidence": 0.0,
  "evidenceIds": []
}
```

Never invent versions.

---

# 31. SAFE SECURITY ANALYSIS

Implement defensive analyzers for:

### HTTP

- response behavior
- content types
- server disclosures
- cache behavior
- redirects

### Security Headers

- CSP
- HSTS
- X-Content-Type-Options
- frame protection
- Referrer-Policy
- Permissions-Policy

### Cookies

- Secure
- HttpOnly
- SameSite
- scope
- expiry indicators

### TLS

- certificate validity
- expiration
- hostname mismatch
- weak configuration indicators

### CORS

- controlled configuration/response behavior checks

### Authentication Surface

Discover and analyze observable configuration around:

- login
- logout
- signup
- password reset
- MFA
- OAuth callbacks
- session endpoints

Do not brute-force authentication.

---

# 32. SAFE ACTIVE CHECKS

Allowed categories include controlled:

- HTTP method behavior checks
- redirect validation
- CORS validation
- safe input-behavior comparisons
- error-response consistency
- observable authorization-boundary inconsistencies
- security configuration checks

Every request must:

- remain in scope
- respect rate limits
- have a timeout
- be logged
- be cancellable

---

# 33. SCANNER ADAPTER CONTRACT

Every scanner outputs:

```json
{
  "scanner": "",
  "scannerVersion": "",
  "observationType": "",
  "asset": "",
  "endpoint": "",
  "method": "",
  "parameter": "",
  "rawSeverity": "",
  "evidence": [],
  "metadata": {}
}
```

Scanner output never goes directly to the final report.

It must pass through:

```text
NORMALIZATION
→ CORRELATION
→ EVIDENCE CHECK
→ FINDING
```

---

# 34. EVIDENCE ENGINE

Evidence is authoritative.

Every evidence object contains:

```text
id
workspaceId
scanId
timestamp
source
asset
request metadata
response metadata
redacted excerpt
hash
```

Redact:

- Authorization headers
- session cookies
- tokens
- passwords
- API keys
- secrets
- sensitive personal data when possible

Never store secrets just because a scanner observed them.

---

# 35. FINDING SCHEMA

Canonical finding:

```json
{
  "id": "",
  "scanId": "",
  "title": "",
  "category": "",
  "severity": "INFO",
  "confidence": 0.0,
  "status": "",
  "cwe": [],
  "owasp": [],
  "asset": "",
  "endpoint": "",
  "method": "",
  "parameter": "",
  "description": "",
  "technicalImpact": "",
  "businessImpact": "",
  "evidenceIds": [],
  "scannerSources": [],
  "remediation": "",
  "manualVerificationRequired": false,
  "firstSeen": "",
  "lastSeen": ""
}
```

Valid severity:

```text
INFO
LOW
MEDIUM
HIGH
CRITICAL
```

Confidence:

```text
0.00 - 1.00
```

---

# 36. FINDING CORRELATION

Merge likely duplicates using combinations of:

- host
- URL
- path
- parameter
- category
- CWE
- scanner source
- response signature
- evidence similarity

Never discard source evidence during deduplication.

---

# 37. QWEN ANALYSIS CONTRACT

Qwen receives structured input only.

Example:

```json
{
  "assessmentPolicy": {},
  "targetMetadata": {},
  "observation": {},
  "evidence": [],
  "knownContext": {}
}
```

Expected output:

```json
{
  "title": "",
  "classification": "",
  "severity": "",
  "confidence": 0.0,
  "cwe": [],
  "owasp": [],
  "description": "",
  "technicalImpact": "",
  "businessImpact": "",
  "reasoningSummary": "",
  "remediation": "",
  "likelyFalsePositive": false,
  "manualVerificationRequired": false,
  "evidenceIds": []
}
```

Validate all model output against a strict schema.

If invalid:

1. retry once with a constrained correction prompt
2. validate again
3. if still invalid, store `AI_ANALYSIS_FAILED`

Never invent fallback evidence.

---

# 38. HALLUCINATION CONTROL

No evidence = no confirmed finding.

The model must not create unsupported claims.

Rules:

```text
insufficient evidence
→ lower confidence

dangerous confirmation required
→ manualVerificationRequired = true

no evidence reference
→ reject output
```

Every important model claim must be traceable to evidence IDs.

---

# 39. WORKER QUEUES

Suggested BullMQ queues:

```text
scan.orchestration
scan.discovery
scan.crawl
scan.api_discovery
scan.fingerprint
scan.http
scan.tls
scan.headers
scan.cookies
scan.cors
scan.normalize
scan.correlate
scan.ai
scan.report
```

Workers require:

- retry
- timeout
- heartbeat
- cancellation
- graceful shutdown
- concurrency limits
- idempotency
- fairness between targets

---

# 40. RESUMABILITY

A worker crash must not destroy a scan.

A server restart must not destroy a scan.

A Qwen provider outage must not destroy a scan.

Persist enough information to resume stages safely.

If a scanner fails:

```text
SCANNER FAILURE
→ record degradation
→ continue safe remaining stages
```

If Qwen fails:

```text
AI_ANALYSIS_DEGRADED
→ deterministic findings remain
→ AI jobs remain retryable
```

---

# 41. COMPLETE SCAN REPORT

Generate:

```text
reports/<scan-id>/scan-report.html
reports/<scan-id>/scan-report.json
reports/<scan-id>/scan-report.pdf-ready.html
```

Required sections:

1. Cover
2. Executive Summary
3. Authorization & Scope
4. Methodology
5. Scan Coverage
6. Scan Timeline
7. Asset Inventory
8. Technology Inventory
9. Security Posture Summary
10. Findings Summary
11. Detailed Findings
12. Coverage Limitations
13. Failed/Degraded Scanners
14. Remediation Priorities
15. Appendix

Risk summary must include:

```text
CRITICAL
HIGH
MEDIUM
LOW
INFO
```

---

# 42. INDIVIDUAL VULNERABILITY REPORTS

Generate one standalone report per finding:

```text
reports/<scan-id>/findings/FIND-0001.html
reports/<scan-id>/findings/FIND-0001.json
```

Each report includes:

- Finding ID
- Title
- Severity
- Confidence
- Status
- CWE
- OWASP
- Affected host
- Affected URL
- Endpoint
- HTTP method
- Parameter where relevant
- Discovery source
- Scanner sources
- Detailed description
- Why it matters
- Technical impact
- Business impact
- Redacted evidence
- Observed behavior
- Expected secure behavior
- Confidence analysis
- False-positive analysis
- Remediation
- Implementation guidance
- Retest guidance
- References
- Discovery time
- Last observed
- Manual verification requirement

Do not include reusable destructive exploitation instructions.

---

# 43. REPORT LANGUAGE QUALITY

Reports must read like professional application-security consulting deliverables.

Do not write:

```text
AI thinks...
```

Prefer:

```text
The assessment observed...
The available evidence indicates...
The finding was classified...
```

Clearly separate:

- observed facts
- inference
- risk assessment
- recommendation

---

# 44. FRONTEND

Required routes:

```text
/login
/workspaces
/targets
/targets/new
/scans
/scans/new
/scans/:id
/scans/:id/assets
/scans/:id/endpoints
/scans/:id/findings
/scans/:id/findings/:findingId
/scans/:id/report
/audit
/settings
```

---

# 45. LIVE SCAN UI

Show real state only.

Example:

```text
Target Authorization        COMPLETE
Scope Validation            COMPLETE
Discovery                   COMPLETE
Crawling                    142 / 231
API Discovery               RUNNING
Fingerprinting              QUEUED
Passive Analysis            QUEUED
Safe Active Analysis        QUEUED
Correlation                 QUEUED
Qwen Analysis               WAITING
Report Generation           WAITING
```

No fake percentages.

No timers pretending work is happening.

---

# 46. OBSERVABILITY

Implement structured logs with:

- requestId
- workspaceId
- scanId
- jobId
- workerId
- scanner

Track:

- scan count
- scan duration
- queue depth
- requests made
- scope-blocked requests
- scanner failures
- AI latency
- model-provider status
- invalid AI output count
- finding count
- report generation time

---

# 47. DOCKER

Provide:

```text
docker-compose.yml
docker-compose.gpu.yml
```

CPU compose should support:

- PostgreSQL
- Redis
- API
- Web
- Worker
- Crawler

GPU model server may be separate.

Do not require the laptop to host the GPU container.

---

# 48. LOCAL AUTHORIZED FIXTURES

Create local deliberately misconfigured test applications.

They may contain safe examples such as:

- missing CSP
- missing HSTS
- weak cookie flags
- verbose error page
- CORS misconfiguration fixture
- unsafe redirect fixture
- server disclosure
- exposed source-map fixture

Do not depend on arbitrary public websites for automated testing.

---

# 49. TESTING

Implement:

- unit tests
- integration tests
- API tests
- RBAC tests
- tenant-isolation tests
- scope tests
- SSRF tests
- DNS rebinding tests
- redirect scope tests
- crawler tests
- crawl-trap tests
- normalization tests
- correlation tests
- deduplication tests
- AI schema tests
- evidence-grounding tests
- worker recovery tests
- report-generation tests

Never claim tests passed unless they were executed.

---

# 50. SECURITY-SPECIFIC TESTS

Mandatory test cases:

```text
target without valid scope cannot scan
redirect outside scope blocked
private IP blocked by default
loopback blocked by default
DNS result revalidated
workspace isolation enforced
VIEWER cannot start scan
AI output without evidence rejected
model-provider outage does not erase findings
scanner crash does not erase scan state
```

---

# 51. DAY-BY-DAY EXECUTION

## DAY 1 — FOUNDATION

Deliver:

- repository audit
- architecture
- Docker
- PostgreSQL
- Redis
- Prisma
- auth
- workspace
- RBAC
- targets
- target scope configuration
- scope engine
- scan state machine
- worker foundation

Notebooks:

```text
00
01
```

---

## DAY 2 — DISCOVERY

Deliver:

- crawler
- discovery engine
- endpoint discovery
- API discovery
- optional browser worker
- technology fingerprinting
- evidence persistence

Notebooks:

```text
02
03
```

---

## DAY 3 — SECURITY ANALYSIS

Deliver:

- HTTP analyzer
- TLS analyzer
- header analyzer
- cookie analyzer
- CORS analyzer
- authentication-surface analyzer
- safe active analysis framework
- scanner adapter system

Notebooks:

```text
04
05
```

---

## DAY 4 — FINDINGS + QWEN

Deliver:

- observation normalization
- finding engine
- deduplication
- correlation
- severity/confidence logic
- Qwen model-provider integration
- model JSON schemas
- prompt-injection defense
- hallucination/evidence controls

Notebooks:

```text
06
07
08
```

---

## DAY 5 — UI + REPORTS

Deliver:

- dashboard
- new scan flow
- live progress
- findings table
- finding details
- asset inventory
- endpoint inventory
- complete scan report
- individual vulnerability reports

Notebooks:

```text
09
10
```

---

## DAY 6 — END-TO-END

Deliver:

- complete integration
- queue recovery
- provider outage handling
- worker restart handling
- test suite
- security hardening
- end-to-end local fixture test

Notebook:

```text
11
```

---

## DAY 7 — SHIP

Do not add major new features.

Perform:

- bug fixes
- performance cleanup
- fresh-install test
- Docker test
- Colab notebook top-to-bottom test
- Qwen endpoint test
- full scan demo
- report quality review
- documentation
- final acceptance run

---

# 52. QUALITY GATE AFTER EVERY MILESTONE

Run:

```text
format
lint
typecheck
unit tests
integration tests
build
```

Fix blockers before continuing.

Do not leave core functionality broken and move to UI polish.

---

# 53. NO-FAKE-FUNCTIONALITY POLICY

Absolutely forbidden:

- fake vulnerabilities
- hardcoded findings presented as scans
- fake scanner output
- fake progress
- fake worker health
- fake model responses
- invented metrics
- invented test results
- invented benchmark values
- hardcoded successful scan status
- hidden fallback mocks
- silent scanner skips

If functionality fails:

SHOW THE FAILURE.

If functionality is incomplete:

MARK IT INCOMPLETE.

---

# 54. REPOSITORY HYGIENE

Before final delivery search for:

```text
TODO
FIXME
placeholder
mock
fake
Not implemented
throw new Error
console.log
.skip
.only
```

Review every occurrence.

Remove temporary debug code.

Do not remove legitimate documentation mentions blindly.

---

# 55. REQUIRED DOCUMENTATION

Create:

```text
README.md
docs/IMPLEMENTATION_AUDIT.md
docs/ARCHITECTURE.md
docs/SECURITY_BOUNDARIES.md
docs/AUTHORIZATION.md
docs/COLAB.md
docs/QWEN27B.md
docs/QLORA.md
docs/MODEL_PROVIDER.md
docs/SCANNING_PIPELINE.md
docs/REPORTS.md
docs/TESTING.md
docs/DEPLOYMENT.md
docs/TROUBLESHOOTING.md
```

---

# 56. .GITIGNORE REQUIREMENTS

Ensure heavy or secret material is excluded:

```gitignore
models/
checkpoints/
datasets/raw/
.env
.env.*
*.safetensors
*.bin
*.gguf
*.pt
*.pth
__pycache__/
.ipynb_checkpoints/
```

Keep `.env.example`.

Never commit:

- model API keys
- tunnel credentials
- target credentials
- session tokens
- production secrets

---

# 57. FIRST ACTION CODEX MUST TAKE

Before implementing anything:

Inspect the entire repository.

Create:

```text
docs/IMPLEMENTATION_AUDIT.md
```

It must contain:

```text
CURRENT STATE
EXISTING ARCHITECTURE
WORKING FEATURES
BROKEN FEATURES
SECURITY GAPS
MISSING COMPONENTS
TARGET ARCHITECTURE
FILES TO CREATE
FILES TO MODIFY
7-DAY DELIVERY BOARD
TOP DELIVERY RISKS
```

Then immediately start implementation.

Do not stop after the audit.

---

# 58. DO NOT REWRITE WORKING CODE WITHOUT A REASON

Prefer surgical integration.

Preserve:

- existing auth
- existing UI
- existing database
- existing deployment
- existing conventions

when they are good enough.

Refactor only when necessary to satisfy reliability, security, or maintainability.

---

# 59. ACCEPTANCE TEST

The project is DONE only when this complete flow works:

```text
1. Start platform
2. Sign in
3. Create/select workspace
4. Register local authorized test target
5. Configure and save the authorized scope
6. Confirm the target is `READY`
7. Start assessment
8. Scope engine validates target
9. Discovery runs
10. Crawler discovers pages
11. Endpoints are persisted
12. Security analyzers run
13. Evidence is persisted
14. Observations are normalized
15. Findings are correlated
16. Duplicates are merged
17. Qwen 27B receives structured evidence
18. Qwen output passes schema validation
19. Findings appear in dashboard
20. Every significant finding links to evidence
21. Complete scan report is generated
22. Individual vulnerability reports are generated
23. Audit log contains scan activity
24. Worker restart does not destroy persisted state
25. Temporary Qwen outage does not destroy deterministic findings
```

---

# 60. FINAL ACCEPTANCE OUTPUT

At the end of implementation, return a final engineering report with:

```text
1. DELIVERED FEATURES
2. ARCHITECTURE
3. FILES CREATED
4. FILES MODIFIED
5. COLAB NOTEBOOK STATUS
6. QWEN CONFIGURATION
7. MODEL PROVIDER STATUS
8. SCANNERS IMPLEMENTED
9. REPORTS IMPLEMENTED
10. TEST RESULTS
11. BUILD RESULTS
12. SECURITY TEST RESULTS
13. KNOWN LIMITATIONS
14. EXACT START COMMANDS
15. EXACT COLAB PROCEDURE
16. EXACT QWEN CONNECTION PROCEDURE
17. EXACT DEMO PROCEDURE
18. SAMPLE SCAN REPORT PATH
19. SAMPLE VULNERABILITY REPORT PATHS
```

Do not claim anything was executed unless it actually was.

---

# 61. DECISION RULES

Whenever choosing between two engineering tasks:

```text
REAL EVIDENCE
>
MORE FINDINGS

WORKING PIPELINE
>
MORE FEATURES

SECURITY BOUNDARIES
>
SCAN AGGRESSIVENESS

RELIABILITY
>
VISUAL POLISH

STRUCTURED MODEL OUTPUT
>
CHATBOT-LIKE MODEL OUTPUT

REAL REPORT
>
DASHBOARD DECORATION

SHIPPING THE END-TO-END FLOW
>
UNNECESSARY FINE-TUNING
```

---

# 62. CORE ENGINEERING PRINCIPLE

The final system must not be:

```text
Qwen + URL = magic
```

It must be:

```text
AUTHORIZED TARGET
        |
        v
CONTROLLED SECURITY TOOLING
        |
        v
STRUCTURED OBSERVATIONS
        |
        v
EVIDENCE
        |
        v
NORMALIZATION
        |
        v
CORRELATION
        |
        v
QWEN 27B REASONING
        |
        v
SCHEMA VALIDATION
        |
        v
PROFESSIONAL FINDINGS
        |
        +-------------------------+
        |                         |
        v                         v
COMPLETE SCAN REPORT     FINDING-SPECIFIC REPORTS
```

---

# 63. START NOW

Read this entire file.

Inspect the repository.

Create `docs/IMPLEMENTATION_AUDIT.md`.

Build the 7-day execution board.

Then begin Day 1 implementation immediately.

Do not ask unnecessary questions.

Do not stop after planning.

Do not generate placeholders instead of working code.

Do not fake successful execution.

Do not weaken authorization protections to make the demo easier.

The single defining success condition is:

# AUTHORIZED URL

# → REAL CONTROLLED ASSESSMENT

# → REAL EVIDENCE

# → REAL FINDINGS

# → QWEN 27B ANALYSIS

# → COMPLETE SCAN REPORT

# → DETAILED VULNERABILITY REPORTS

Everything else is secondary.
