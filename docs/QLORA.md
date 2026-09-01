# QLoRA Workflow

Fine-tuning is optional and is not an acceptance dependency. The deterministic assessment pipeline and base Qwen model remain deployable without an adapter.

Notebook 04 prepares tokenization and memory-aware presets. Notebook 05 performs resumable 4-bit NF4 QLoRA training with PEFT, gradient checkpointing, gradient accumulation, and frequent checkpoints. Notebook 06 compares the base and adapter on the identical held-out set.

An adapter is eligible for deployment only when important JSON compliance, evidence grounding, and unsupported-claim controls do not regress. Missing hardware, failed loads, interrupted training, and worse evaluation results are surfaced rather than replaced with synthetic success.

Checkpoint and model files belong in ignored `checkpoints/` and `models/` paths or mounted Drive storage. They must not be committed to the repository.
