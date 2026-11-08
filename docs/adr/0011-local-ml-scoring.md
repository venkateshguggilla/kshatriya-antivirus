# ADR 0011: Optional local machine-learning scoring without a native runtime

- Status: accepted (M9)
- Date: 2026-11-08

## Context

The roadmap called for "EMBER-style features, ONNX, off by default". Two facts changed the recommendation:

1. ONNX Runtime is a large native library that would parse model files inside the sandboxed worker,
   adding native attack surface to the one process that must stay small and memory-safe.
2. No trained model exists for this project, and training one needs a labelled corpus that this
   repository must never contain (AGENTS rule 4).

## Decision

- **Features (`pe-v1`, 296 values):** byte histogram (256), histogram of 1 KiB window entropies (16)
  and 24 header, section and import facts from the existing bounds-checked `PeImage`.
- **Model format:** strict JSON (`*.model.json`), either logistic regression (one weight per feature) or
  a gradient-boosted tree ensemble (the shape LightGBM/XGBoost export; at most 5,000 trees of 8,192
  nodes). Children must follow their parent, so evaluation always terminates. Fuzzed (`Sentinel.Fuzz model`).
- **Evaluation in pure C#** inside the sandboxed worker (`MlEngine`). No native runtime, no dependency.
- **Results are `suspicious` only** (low, or medium at score ≥ 0.95), never `malware`, never actioned
  automatically. Validly signed files are skipped.
- **Off by default:** models arrive only in signed content packages ([ADR 0008](0008-signed-content-updates.md))
  and are used only when `machineLearning: true` is set in the protected `service.json`.
  `sentinel scan --model <file>` exists for local evaluation.

## Consequences

- No model ships. Until one is trained, evaluated against a benign corpus and a labelled malware set,
  and published as signed content, the ML engine does nothing. No detection-quality claim is made.
- A future model needs a documented training pipeline (outside this repository), feature-set versioning
  (`pe-v2` would be a new engine content version) and false-positive measurement (M12).
- ONNX can be reconsidered for models that trees and linear models cannot express, but only out of
  process and after review.
