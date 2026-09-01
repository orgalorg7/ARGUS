# Qwen 27B Runtime

The required default model identifier is `Qwen/Qwen3.8-27B`. Core reasoning must use a self-hosted deployment; proprietary model APIs are not a fallback.

The developer host is not a model runtime. Notebook 00 executed on this host and detected no CUDA GPU, no PyTorch, and no Transformers stack. It therefore marked BF16, FP16, INT8, and INT4 as `NOT_VIABLE` and did not attempt a load. This is the expected safe behavior.

Production serving uses a private vLLM-compatible API. `docker-compose.gpu.yml` exposes port 8000 only inside `aasp-private`. The API key is injected at runtime. The model service receives structured observations and evidence; it receives no unrestricted network client, target credentials, queue administration, or scope mutation capability.

Day 4 implements a workspace-scoped provider registry, AES-256-GCM provider-key encryption, explicit provider health checks, and an OpenAI-compatible vLLM client. The client keeps system policy separate from target-controlled text, retries one invalid response with a correction request, validates strict JSON, and rejects evidence identifiers that were not supplied in the analysis input.

The worker never asks Qwen to scan a URL. It submits a deterministic finding plus persisted, redacted evidence. A temporary outage of a configured provider moves the scan to `AI_ANALYSIS_WAITING_FOR_PROVIDER`; deterministic findings remain in PostgreSQL and can resume. With no configured provider, AI is marked degraded and deterministic reports continue.

No model result has been generated on the developer host. Notebooks 08, 09, and 11 require a suitable remote CUDA runtime. Notebook 11 checkpoints every raw and validated response and refuses to run without `QWEN_BASE_URL`.

## Colab runtime and contract test

`notebooks/08_qwen27b_inference_api.ipynb` is the canonical single-notebook Colab path for an unquantized Qwen3.8-27B test. It runs top-to-bottom and:

- installs a current vLLM release and records the resolved version;
- removes TorchAudio only when Colab has installed a CUDA-incompatible optional build;
- requires the `HF_TOKEN` and `QWEN_API_KEY` Colab secrets without printing either value;
- requires at least 75 GiB of detected VRAM and 70 GiB of free runtime disk;
- stores model weights under `/content/aasp-huggingface-cache`, never Google Drive;
- binds vLLM to `127.0.0.1:8000` with API-key authentication and no public tunnel;
- safely reuses an already-running localhost service only when health, the configured API key, and the exact model identifier all validate;
- waits for actual service health and preserves the real server log on failure;
- verifies that an unauthenticated model-list request is rejected;
- submits structured evidence containing target-controlled prompt-injection text;
- constrains the response with JSON Schema and independently validates field types, severity, confidence, and evidence identifiers; and
- saves the response, non-secret provider metadata, and server log under `/content/aasp-results`.

A successful run creates `/content/aasp-qwen-test-results.zip`. This archive is small enough to download from the Colab Files sidebar. The model cache is intentionally ephemeral and disappears when the Colab runtime is destroyed.

The notebook is generated deterministically by `scripts/build_qwen_colab_notebook.py`. Regenerate it after editing the builder, then validate both the notebook JSON and every Python code cell before distribution.

For a single benchmark run that should not leave an expensive Colab GPU allocated, use `notebooks/QWEN38_COLAB_RUN_ALL_AND_STOP.ipynb`. It performs the same guarded startup and strict contract test, creates and downloads the result archive, stops the vLLM process, waits two minutes for the browser download, and requests runtime release. The user must confirm that Colab displays `Disconnected`; if it does not, select **Runtime → Disconnect and delete runtime** immediately.

For the actual local-platform integration, use `notebooks/QWEN38_COLAB_PRIVATE_TAILSCALE_SERVER.ipynb` with `scripts/run-local-with-colab-qwen.sh`. The notebook keeps vLLM on loopback and uses tailnet-only Tailscale Serve; the script refuses public model URLs, verifies access from inside the worker container, runs the authorized fixture pipeline, validates persisted AI analyses, and copies both report layers locally. See `docs/COLAB_LOCAL_DEMO.md` for the exact procedure.
