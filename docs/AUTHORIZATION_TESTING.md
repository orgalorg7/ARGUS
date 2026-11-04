# Authenticated multi-identity authorization testing

Argus treats authorization testing as a configured, evidence-driven scan stage. It does not enumerate arbitrary IDs or import browser state files from the repository.

## Architecture

- `AssessmentIdentity` stores a label, role, tenant, authentication type, health state, metadata, and an AES-256-GCM credential envelope.
- `AuthorizedResource` stores an operator-approved external identifier, provenance, owner, tenant, and endpoint variables.
- `ResourceIdentityRelationship` records `OWNS`, membership, administrative, management, tenant, and sharing relationships.
- `AuthorizationTestCase` binds one resource and action to an identity set and expected `ALLOW`/`DENY` policy.
- `AuthorizationTestResult` stores the redacted matrix for one scan and test case.
- `@aasp/authorization-engine` owns isolation, response normalization, structural comparison, confidence, and grouping.
- `scan.authorization` executes after safe-active scanning and before observation normalization.

## Secret setup

Generate a dedicated encryption key. Do not reuse the JWT or Qwen provider key.

```bash
openssl rand -base64 32
```

Set the output as `IDENTITY_SECRET_ENCRYPTION_KEY` in the private runtime environment. The API encrypts credential material before persistence. The worker decrypts it only while preparing that identity and clears the in-memory request context at stage completion or cancellation.

API reads never return credential ciphertext, passwords, cookies, tokens, request bodies, or raw authentication failures. Logs redact secret-bearing keys and bearer/JWT patterns. Evidence stores response structure, redacted excerpts, and fingerprints rather than sensitive field values.

## Configure an identity

Use the Authorization UI or the API. The credential object must match `authenticationType`.

```http
POST /api/workspaces/{workspaceId}/targets/{targetId}/authorization/identities
Content-Type: application/json
```

```json
{
  "label": "Alice",
  "role": "USER",
  "tenant": "ACME",
  "authenticationType": "CUSTOM_HEADERS",
  "credential": {
    "headers": {
      "x-authorized-test-identity": "operator-supplied-value"
    }
  },
  "metadata": {}
}
```

Supported static runtime types are anonymous, bearer token, API key, session cookie, and custom headers. Username/password, OAuth/OIDC, and login automation are adapter types: their credential/configuration schema is accepted and encrypted, but a deployment must register its application-specific login adapter. If no adapter is registered, only that identity is marked unavailable and eligible comparisons continue with degraded coverage.

## Register an approved resource

```http
POST /api/workspaces/{workspaceId}/targets/{targetId}/authorization/resources
```

```json
{
  "resourceType": "order",
  "externalId": "order-fixture-alice",
  "tenant": "ACME",
  "ownerIdentityId": "identity-id-for-alice",
  "provenance": "OPERATOR_SUPPLIED",
  "endpointVariables": {},
  "metadata": {},
  "relationships": []
}
```

Allowed provenance is operator-supplied, scanner-created during this assessment, approved seed, or previously observed as belonging to a supplied identity. Random identifier mutation is not part of the engine.

## Define expected policy

```http
POST /api/workspaces/{workspaceId}/targets/{targetId}/authorization/test-cases
```

```json
{
  "name": "Order read boundary",
  "resourceId": "approved-resource-id",
  "action": "READ",
  "endpointTemplate": "https://client.example/api/orders/{resourceId}",
  "method": "GET",
  "identityIds": ["alice-id", "bob-id", "manager-id", "admin-id", "anonymous-id"],
  "expectedPolicy": {
    "alice-id": "ALLOW",
    "bob-id": "DENY",
    "manager-id": "ALLOW",
    "admin-id": "ALLOW",
    "anonymous-id": "DENY"
  },
  "mutationRisk": "READ_ONLY",
  "mutationExplicitlyAuthorized": false,
  "cleanupStrategy": "NONE",
  "requestHeaders": {},
  "followRedirects": false,
  "timingSamples": 1
}
```

Placeholders resolve only from the selected approved resource. The final URL is scope-checked immediately before transport. Redirects are recorded and an out-of-scope destination is rejected before connection.

## Mutation gate

`POST`, `PUT`, `PATCH`, and `DELETE` are rejected unless all of these are true:

1. `mutationExplicitlyAuthorized` is `true`.
2. `mutationRisk` is `DISPOSABLE_TEST_FIXTURE`.
3. `cleanupStrategy` is not `NONE`.
4. A deployment-specific cleanup adapter is registered and completes after each request.
5. The resource provenance is approved.
6. The final URL, method, identity, resource, and action pass test-case and network-scope checks.

The stock worker deliberately has no generic cleanup adapter, so it refuses state-changing test cases. A deployment must supply a cleanup implementation for its own disposable fixtures before those methods can execute. Repeated timing samples are disabled for mutations. Never point a mutation test at an arbitrary production object.

## Differential algorithm

The owner or first expected-allow observation becomes the baseline. Each other identity is classified as owner, same-role non-owner, higher/lower role, cross-tenant, anonymous, or other. Comparison considers:

- HTTP status and redirect location/chain
- media type and selected cache/authentication headers
- normalized JSON field-path similarity
- overlap of sensitive field paths without retaining their values
- normalized body fingerprint and error shape
- authentication health
- expected-policy violation
- stable bounded repeat samples

Timing never proves a finding and contributes only contextual data. Severity describes impact; confidence describes evidence quality. Authentication expiry suppresses authorization conclusions rather than becoming a BOLA finding.

## Browser isolation

`BrowserContextManager` creates exactly one context per identity and rejects adapters that return the same context instance twice. Anonymous bootstrap rejects any session fingerprint. `PlaywrightBrowserAdapter` accepts an injected, sandboxed Playwright `Browser`, creates a fresh context with downloads disabled and service workers blocked, then loads only that identity's in-memory headers/cookies. It never writes `storageState` to disk. The current worker pipeline performs HTTP matrix execution; deployments enabling browser flows must supply and lifecycle-manage the Playwright browser process through this adapter.

## Results and limitations

Open a completed scan's **Authorization** tab to inspect each matrix cell. The complete technical report contains the same expected-versus-observed matrix and clearly marks unavailable identities.

The engine can establish that configured test identities received inconsistent behavior on approved fixtures. It cannot infer the client's intended policy when `UNKNOWN` is configured, prove security from denials, or safely confirm business impact that requires unrelated user data or destructive actions. Such cases remain inconclusive or require authorized manual verification.
