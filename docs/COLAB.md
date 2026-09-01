# Colab Workflow

## Day 1 notebooks

### 00_environment_gpu_check.ipynb

Run before installing or loading model weights. It detects the runtime, CUDA/GPU/VRAM, RAM, disk, Drive mount, and relevant Python packages. It estimates BF16, FP16, INT8, and INT4 memory independently and writes:

```text
artifacts/environment_report.json
artifacts/model_compatibility_report.json
```

It never attempts model loading. `AASP_MOUNT_DRIVE=1` enables the optional Colab Drive mount.

### 01_security_dataset_ingestion.ipynb

Place provenance-reviewed `.json` or `.jsonl` records in `datasets/raw`. The notebook rejects malformed or incomplete records, duplicate sample IDs, missing evidence, invalid confidence, invalid severity, and malformed CWE labels before atomically writing:

```text
datasets/processed/security_dataset.jsonl
```

The committed `defensive_seed.jsonl` contains two explicitly identified local-fixture training examples. They are dataset records, not assessment output.

## Day 2 notebooks

### 02_dataset_cleaning.ipynb

Reads the normalized dataset, detects malformed or empty records, invalid severity/CWE values, missing evidence, exact and near duplicates, unusually long samples, possible secret leakage, and train/test overlap. It writes:

```text
datasets/processed/security_dataset.cleaned.jsonl
evaluations/dataset_quality_report.json
evaluations/dataset_quality_report.csv
```

The committed run processed the two local-fixture records without reporting quality issues. This result describes only those two records and is not presented as representative model-training coverage.

### 03_qwen27b_baseline.ipynb

Benchmarks only the configured private Qwen endpoint and requires the endpoint's model inventory to contain `Qwen/Qwen3.8-27B`. It preserves every response and measures schema compliance, classification, mappings, remediation, evidence grounding, and unsupported-claim signals.

The notebook deliberately has no synthetic, proprietary, or canned-response fallback. It was executed on the current host and stopped with a clear configuration error because `QWEN_BASE_URL` and `QWEN_API_KEY` were unavailable; therefore no baseline metrics are claimed.

## Day 3 notebooks

### 04_qwen27b_qlora_prepare.ipynb

Validates the exact primary model identifier, cleaned dataset, GPU/VRAM, memory-aware preset, chat formatting, and tokenizer-derived sequence lengths before training. Presets are `LOW_MEMORY`, `STANDARD`, and `HIGH_MEMORY`; an insufficient runtime produces an explicit compatibility warning and does not load model weights.

### 05_qwen27b_qlora_train.ipynb

Implements 4-bit NF4 QLoRA with PEFT, gradient checkpointing, gradient accumulation, frequent checkpoints, automatic checkpoint resume, and artifact validation. Configuration is exposed through the contract variables `MODEL_ID`, `DATASET_PATH`, `OUTPUT_DIR`, `MAX_SEQ_LENGTH`, `BATCH_SIZE`, `GRAD_ACCUM`, `LR`, `EPOCHS`, `LORA_R`, `LORA_ALPHA`, and `LORA_DROPOUT`.

Both notebooks support `AASP_MOUNT_DRIVE=1`. Notebook 05 refuses to load Qwen 27B without CUDA or with less than the LOW_MEMORY preset's 24 GiB VRAM gate. These notebooks were syntax-validated on the developer host but not executed there because PyTorch/CUDA and sufficient GPU memory are absent; no training result is claimed.

## Day 4 notebooks

### 06_qwen27b_posttrain_eval.ipynb

Loads the same held-out records for the base and adapter variants, saves every raw response, compares schema, severity, mapping, grounding, unsupported-claim, and remediation-presence metrics, and recommends the base model if an important grounding metric regresses.

### 07_qwen27b_quantization.ipynb

Evaluates only explicitly requested profiles. Each profile is recorded as `INCOMPATIBLE`, `FAILED`, or `LOADED_AND_TESTED`, with measured footprint, peak VRAM, latency, throughput, and JSON compliance only after a real load and generation.

### 08_qwen27b_inference_api.ipynb

Starts an authenticated vLLM server after a CUDA/VRAM gate, waits for a real health response, performs a structured evidence test, and saves non-secret endpoint metadata. It binds to loopback by default and deliberately creates no public tunnel. Use a private VPN or SSH tunnel from the platform network.

The Day 4 notebooks are syntax-validated locally but have not been executed against a GPU or Qwen weights; no evaluation, quantization, or inference result is claimed.

For a private connection from the local Docker worker to an ephemeral Colab model runtime, use `QWEN38_COLAB_PRIVATE_TAILSCALE_SERVER.ipynb`. It requires an ephemeral Tailscale auth key and publishes only a tailnet-only authenticated endpoint. The end-to-end local launcher and complete operator procedure are documented in `docs/COLAB_LOCAL_DEMO.md`.

### 08_qwen27b_inference_test.ipynb

Exercises the configured private Qwen API with structured security evidence, validates the strict analysis schema and evidence-ID grounding, and checkpoints raw and validated responses. This is the canonical contract-named inference test; the `_api` notebook is the vLLM server-start companion.

## Day 5 notebooks

### 09_finding_reasoning_pipeline.ipynb

Reads scanner observations, invokes Qwen only with separated policy/context/evidence data, rejects malformed or ungrounded outputs, and writes `ai_findings.json`. It requires the private provider variables and contains no model fallback.

### 10_security_report_generation.ipynb

Generates the complete HTML/JSON report layer and one HTML/JSON report per evidence-backed finding. It refuses findings without evidence and does not claim Qwen analysis unless a validated model artifact is supplied.

## Day 6 notebook

### 11_end_to_end_authorized_demo.ipynb

Runs the owned loopback fixture through the real Day 3 scanner and Day 4 correlation demonstrations, requires an actual private Qwen endpoint for analysis, validates every model response and evidence ID, then invokes the Day 5 report generator and verifies both report layers. Expensive/raw results are checkpointed. If Qwen is unavailable, the notebook fails visibly instead of generating substitute output.

All notebooks 00-11 are notebook-JSON and Python-syntax validated. Notebook 11 has not been executed on this non-GPU host, so no Qwen-backed end-to-end result is claimed yet.

## Ephemeral storage rule

Use Drive for expensive checkpoints and copy validated artifacts before the Colab runtime disconnects. Notebooks must not assume `/content` persists. API keys and tunnel credentials are runtime environment variables and must not be written into notebook source or committed output.
