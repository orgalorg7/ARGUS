# Model Provider

The primary model is `Qwen/Qwen3.8-27B`, served through an authenticated vLLM-compatible endpoint. The provider has no scanner tools, target credentials, scope controls, queue administration, or unrestricted network client.

## Configuration boundary

Provider configuration is workspace-scoped. Creating or changing it requires:

- an authenticated workspace `OWNER` or `ADMIN`;
- `isSystemAdmin == true` on the authenticated user; and
- an exact or wildcard-suffix match in `QWEN_PROVIDER_ALLOWED_HOSTS`.

This prevents an ordinary workspace administrator from using provider health checks as an arbitrary server-side request primitive. Provider URLs reject embedded credentials, query parameters, fragments, and non-HTTP schemes.

When an API key is supplied, `MODEL_PROVIDER_ENCRYPTION_KEY` must decode to exactly 32 bytes (base64 or 64 hexadecimal characters). Keys are encrypted with AES-256-GCM. API responses expose only `apiKeyConfigured`; plaintext and ciphertext are never returned.

Generate a key:

```bash
openssl rand -base64 32
```

## API

```text
GET  /api/workspaces/:workspaceId/model-providers
POST /api/workspaces/:workspaceId/model-providers
POST /api/workspaces/:workspaceId/model-providers/:providerId/health
```

Example body:

```json
{
  "name": "private-qwen",
  "baseUrl": "http://qwen:8000",
  "modelName": "Qwen/Qwen3.8-27B",
  "apiKey": "runtime-secret-from-secret-manager"
}
```

The endpoint is dynamic database configuration and does not require rebuilding the platform. The hostname still must be pre-authorized through the deployment allowlist.

## Failure behavior

- No configured provider: scan and stage enter the explicit waiting state.
- Network, timeout, throttling, or provider 5xx: provider is marked offline and the persisted job waits for recovery.
- Invalid JSON or invented evidence IDs: one constrained retry is attempted; a second failure is persisted with the database `FAILED` analysis status.
- Per-finding analysis failure: deterministic findings remain and report generation can continue in degraded mode.

The current developer host has not executed Qwen 27B inference. Provider integration is tested with protocol-level test doubles only; no model metrics are claimed.
