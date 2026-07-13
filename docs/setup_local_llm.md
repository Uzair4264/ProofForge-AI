# Setting up a local LLM (Ollama) for ProofForge AI

ProofForge runs the full pipeline offline with the built-in **mock** backend (no model
needed — that's what the tests use). To get *real* field inference and claim
verification, point it at a local **Ollama** model. This guide targets the project's
reference hardware (Windows, 8 GB RAM, Intel i5-11th-gen, Iris Xe) and the pinned
model `qwen2.5:3b-instruct-q4_K_M`.

Everything stays on your machine — no cloud, no telemetry.

---

## 1. Install Ollama

**Windows (recommended):**
```powershell
winget install --id Ollama.Ollama -e
```
Or download the installer from <https://ollama.com/download>.

After installing you may need to **open a fresh terminal** so `ollama` is on your PATH.
Ollama runs as a background service and serves its API at `http://localhost:11434`.

Verify:
```powershell
ollama --version
```

## 2. Pull the model

```powershell
ollama pull qwen2.5:3b-instruct-q4_K_M
```
This is roughly a 2 GB download. The q4 quantization runs comfortably in ~3–4 GB of
RAM, which fits an 8 GB machine alongside a browser/Burp.

Confirm it's present:
```powershell
ollama list
```

> Have more RAM (16 GB+)? You can switch to `qwen2.5:14b-instruct-q4_K_M` for better
> inference — just set it in the config (next step) instead.

## 3. Point ProofForge at Ollama

The config lives at the OS-appropriate location (run `bbreport config path` to see it).
The defaults already specify the Ollama backend and this model, so the simplest switch is:

```powershell
bbreport config init --force
```

This rewrites the config to defaults:
```yaml
llm:
  backend: ollama
  model: qwen2.5:3b-instruct-q4_K_M
  endpoint: http://localhost:11434
  temperature: 0.1
  max_tokens: 1024
  timeout_seconds: 120
```
(If you'd rather keep other settings, just edit `backend: mock` → `backend: ollama` in
that file by hand.)

## 4. Pre-flight check

```powershell
bbreport doctor
```
You want to see:
```
[OK] Ollama reachable at http://localhost:11434
[OK] Model 'qwen2.5:3b-instruct-q4_K_M' is pulled
```
If Ollama isn't reachable, make sure the service is running (`ollama serve`, or just
launch the Ollama app once). If the model isn't pulled, re-run step 2.

## 5. What to expect on this hardware

- **First call is slow** — Ollama loads the model into memory on the first request.
- A single inference call is ~10–30 s; a full report makes ~10–18 calls, so end-to-end
  is typically **several minutes** (most of v0's runtime is the model thinking). This is
  expected and acceptable for a once-per-report tool (spec §7.6, §18).
- Results are **cached** by prompt hash, so re-running `verify`/`check` is instant.
  Pass `--no-cache` while you're tuning prompts to force fresh calls.

## 6. Switching back to offline/mock

For fast, deterministic runs (e.g. demos, or while writing templates), set
`llm.backend: mock` again — the whole pipeline still works, returning canned values.

---

Next: walk a real finding end-to-end in
[walkthrough_juiceshop_dom_xss.md](walkthrough_juiceshop_dom_xss.md).
