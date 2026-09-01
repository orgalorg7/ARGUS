# GPU Deployment

Production Qwen serving belongs on a persistent GPU host, not the CPU platform or an Internet-exposed endpoint. Measure VRAM with notebook 00 before selecting BF16, FP16, 8-bit, or supported 4-bit deployment. Do not claim a configuration loaded until vLLM reports readiness and notebook 08 validates strict responses.

```bash
export QWEN_API_KEY="$(openssl rand -base64 48)"
export QWEN_MODEL='Qwen/Qwen3.8-27B'
export QWEN_DTYPE=auto
export QWEN_TENSOR_PARALLEL_SIZE=1
export QWEN_GPU_MEMORY_UTILIZATION=0.88
export QWEN_MAX_MODEL_LEN=8192
export QWEN_BIND_ADDRESS=127.0.0.1
docker network create aasp-private || true
docker compose -f docker-compose.gpu.yml up -d
```

The safe default publishes vLLM only on GPU-host loopback. For a separate CPU host, set `QWEN_BIND_ADDRESS` to the GPU host's private VPC/VPN address—never `0.0.0.0` on an Internet-routable interface—and permit TCP 8000 only from the CPU backend. Add that private hostname or address to `QWEN_PROVIDER_ALLOWED_HOSTS`, configure the provider with the private vLLM URL and the same bearer token, and verify the container health check before scanning. Docker `expose` alone is sufficient only when CPU and GPU containers share the same Docker network on one host.

The model receives no scanner network client, target credentials, scope mutation, queue administration, or shell. The current developer host has no NVIDIA runtime, so only Compose rendering and fail-loud hardware diagnostics were executed here; a successful model load is not claimed.

Colab is a temporary MVP validation option. Generate its bearer token inside the notebook, connect through an authenticated private tunnel, and copy checkpoints to durable storage before the runtime ends. A Colab tunnel is not the production topology.
