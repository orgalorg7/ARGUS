# Colab Qwen to Local Platform Demo

This is the supported development topology when the laptop runs the platform but cannot run Qwen:

```text
Local Docker platform
  worker
    -> encrypted Tailscale connection
      -> tailnet-only Tailscale Serve port
        -> Colab loopback vLLM
          -> Qwen/Qwen3.8-27B
```

vLLM remains bound to `127.0.0.1` inside Colab. Tailscale Serve exposes the authenticated API only to the private tailnet. The development endpoint uses tailnet-only HTTP because the Tailscale transport is already WireGuard-encrypted; vLLM still requires its bearer API key. Do not use Tailscale Funnel, ngrok, Cloudflare Quick Tunnels, or another public tunnel for this model endpoint.

## 1. Install and connect Tailscale on the laptop

Install Tailscale using the instructions for the laptop operating system, sign in, and verify that the backend is running:

```bash
tailscale status
```

Official installation documentation: <https://tailscale.com/kb/1017/install>

## 2. Create runtime secrets

Create a Hugging Face read token with access to `Qwen/Qwen3.8-27B`.

Generate the model API key locally:

```bash
openssl rand -hex 32
```

Keep the result in a password manager temporarily. The same exact value is added to Colab as `QWEN_API_KEY` and entered into the local launcher. It is never committed.

In the Tailscale admin console, create an auth key with these settings:

- one-off;
- ephemeral;
- pre-approved if device approval is enabled; and
- the shortest practical expiry.

The Colab node is temporary. Revoke a key immediately if it is exposed. Auth-key documentation: <https://tailscale.com/docs/features/access-control/auth-keys>

## 3. Start the private Qwen server in Colab

Open this local file in Google Colab:

```text
notebooks/QWEN38_COLAB_PRIVATE_TAILSCALE_SERVER.ipynb
```

Select an A100 80 GB high-RAM runtime. In the Colab Secrets panel, add and enable notebook access for:

```text
HF_TOKEN
QWEN_API_KEY
TS_AUTHKEY
```

Run the notebook from the first cell. Do not paste individual Python fragments into a separate notebook. Model download and startup can take time; success is not declared until real health, authentication, model identity, strict JSON, and evidence-grounding checks pass.

The private endpoint cell eventually prints a value similar to:

```text
QWEN_BASE_URL=http://aasp-colab-qwen-abcdef.example-tailnet.ts.net
```

If Tailscale Serve prints an enablement URL, open it once, approve Serve for the tailnet, and rerun that cell. This does not enable public Funnel access.

Run the final keepalive cell and leave it running. It has a two-hour safety cap.

## 4. Run the complete platform and real demo locally

From the repository root on the laptop:

```bash
bash scripts/run-local-with-colab-qwen.sh demo
```

On first use, the launcher asks for:

```text
QWEN_BASE_URL
QWEN_API_KEY
```

Paste the tailnet-only HTTP `.ts.net` URL printed by Colab and the same API key stored in Colab Secrets. The launcher writes `.env.aasp-local` with mode `0600`; `.gitignore` excludes it.

The launcher then:

1. rejects non-Tailscale provider URLs;
2. verifies local Tailscale connectivity;
3. checks Qwen health, authentication, and exact model identity from the host;
4. builds and starts PostgreSQL, Redis, API, web, worker, and the owned fixture;
5. checks Qwen connectivity from inside the Docker worker;
6. creates a workspace and privileged-approved local fixture target;
7. persists `VERIFIED` authorization;
8. starts a real `LIGHT` scan;
9. prints only real persisted state changes;
10. requires evidence-backed findings;
11. requires persisted Qwen analyses with valid schema and evidence IDs;
12. requires complete and finding-specific reports; and
13. copies the reports from Docker into the local repository.

The command fails visibly if any required stage fails.

## 5. Open the output

The launcher prints the real scan identifier and exact report location. The output is under:

```text
reports/<scan-id>/scan-report.html
reports/<scan-id>/scan-report.json
reports/<scan-id>/scan-report.pdf-ready.html
reports/<scan-id>/findings/FIND-*.html
reports/<scan-id>/findings/FIND-*.json
artifacts/qwen-colab-runtime-acceptance.json
```

Open `reports/<scan-id>/scan-report.html` in a browser. The individual vulnerability reports are in its `findings` directory.

The UI remains available at:

```text
http://127.0.0.1:3000/login
```

The login email is `admin@local.test`. Read the generated password without printing the other secrets:

```bash
grep '^ADMIN_PASSWORD=' .env.aasp-local
```

## 6. Stop compute and local services

After the launcher copies the reports, stop the final Colab keepalive cell. Its `finally` block stops vLLM, removes Tailscale Serve, logs out the ephemeral node, and requests runtime release. Confirm Colab shows **Disconnected**. Otherwise select **Runtime -> Disconnect and delete runtime**.

Stop the local services while preserving PostgreSQL, Redis, and report volumes:

```bash
bash scripts/run-local-with-colab-qwen.sh stop
```

## Later Colab sessions

Each ephemeral Colab node normally receives a different Tailscale IP. Update only the model connection without rotating the database or login secrets:

```bash
bash scripts/run-local-with-colab-qwen.sh connect
bash scripts/run-local-with-colab-qwen.sh start
```

Other launcher commands are:

```bash
bash scripts/run-local-with-colab-qwen.sh scan
bash scripts/run-local-with-colab-qwen.sh status
bash scripts/run-local-with-colab-qwen.sh logs
```

`scan` runs a fresh authorized fixture assessment against an already healthy stack without rebuilding images. `demo` performs the build/start checks first.

## Boundaries and limitations

- Colab is an ephemeral development inference worker, not a production GPU server.
- The local scan survives a temporary model outage because deterministic evidence and findings are persisted.
- A disconnected provider may leave a scan in `AI_ANALYSIS_WAITING_FOR_PROVIDER`; reconnect a provider and resume it through the platform workflow.
- The A100 run has not been executed from this developer host. Notebook structure and Python syntax can be validated locally, but GPU loading and cross-tailnet connectivity require the real Colab runtime.
