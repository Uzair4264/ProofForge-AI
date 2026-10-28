# ProofForge AI

> A local-first AI assistant that helps bug bounty researchers produce **evidence-backed,
> program-compliant** reports — and **refuses to fabricate**.

ProofForge reads the evidence you captured, infers what it can, **traces every claim back to the
evidence that supports it**, enforces the target program's policy, and renders a submission-ready
report — all on your machine. It is *not* a scanner, *not* an exploit generator, and *not* a
"the-AI-writes-it-for-you" tool.

**CLI:** `proofforge` · **Package:** `proofforge-ai` · **License:** Apache-2.0 · **Status:** v0 (early)

---

## The gap it fills

Most "AI report writers" are GPT wrappers: you describe a bug, they emit plausible prose with no
grounding. Triagers are drowning in this unverified junk, and pasting an embargoed PoC into a cloud
chatbot leaks sensitive data. ProofForge takes the opposite stance, applying two ideas from agentic-AI
security research to the *report* itself:

- **Action-level reasoning (integrity).** Every claim in the report is a node in a claim→evidence
  graph. The tool detects **orphan claims** (no evidence), **over-reach** (claiming more than the
  evidence shows), and **inconsistencies** — before you submit.
- **Domain-specific supervision (compliance).** Each bug bounty program is encoded as a **rule pack**
  (YAML) that enforces scope, required fields, forbidden content, and severity framework.

| | Generic AI writer | **ProofForge AI** |
|---|---|---|
| Source of claims | whatever you type (hallucinates) | **only your real evidence** |
| Integrity | none | **every claim traced to evidence** (orphan / over-reach checks) |
| Program rules | ignored | **scope / required fields / forbidden content** enforced |
| Severity | guessed | **deterministic CVSS v3.1, capped at what the evidence demonstrates** |
| Privacy | sent to the cloud | **local by default** |
| Auditability | none | **hash-chained, tamper-evident log** |

## Status (v0)

- **7 vulnerability classes:** XSS, SSRF, IDOR, CSRF, SQLi, information disclosure, open redirect —
  each a YAML template (no Python to add more). Access control, auth bypass / account takeover and RCE
  are next.
- **Full 6-stage pipeline:** ingestion & classification → inference → adaptive elicitation → integrity
  verification → compliance enforcement → rendering.
- **Local LLM** via Ollama (`qwen2.5:3b-instruct-q4_K_M`), with an offline **mock** backend and an
  opt-in cloud backend behind the same interface.
- **Deterministic core:** CVSS v3.1, scope/field/forbidden-content checks, claim→evidence DAG,
  hash-chained audit log.
- **Evidence-derived severity ceiling:** each class starts at what the bare finding proves, and each
  CVSS metric can only rise when its own evidence is shown (e.g. SQLi starts at 7.5; integrity and
  availability impact need a demonstrated write or code execution).
- **Deterministic evidence checks (no LLM):** requests from two distinct accounts or roles (compared by
  credential hash, never the token), blind SQLi true/false response pairs, time-based SQLi delays that
  scale with the payload (researcher-entered timings; ProofForge never replays requests), and open
  redirects that actually leave the target's site.
- **"Usually rejected" pre-check:** warns before you submit findings platforms commonly close as N/A or
  P5 (bare open redirects, version banners, keys meant to be public) and says how to upgrade them.
- **Offline mode:** every class runs end-to-end on the built-in mock backend (no model needed).
- **Live-validated once so far:** a real OWASP Juice Shop DOM-XSS, captured in Burp, run through the
  full pipeline on the local model. The other classes have not yet been validated against a live
  model and real evidence.

Several integrity and compliance checks are still being hardened.

## How it works

```
Evidence (HTTP, screenshots, repro)  ─►  Ingest & classify  ─►  Infer fields (LLM)
   ─►  Confirm/elicit  ─►  Integrity (Gap 1)  ─►  Compliance (Gap 3)  ─►  report.md + audit.jsonl
```

Deterministic code decides where rules exist; the LLM is called only for narrow natural-language
sub-tasks (classification, field inference, claim verification) and is always **advisory** — you
confirm every value before it lands in the report.

Workflow and architecture diagrams: **[diagram.md](diagram.md)**.

## Project layout

```
src/proofforge/      the package — cli/, core/, evidence/, inference/, elicitation/,
                     vuln_classes/ (YAML templates), program_packs/ (YAML rule packs),
                     severity_frameworks/, output_formats/, audit/, llm_backends/, prompts/
docs/                local LLM setup, Juice Shop walkthrough
diagram.md           workflow and architecture diagrams
```

## Install (development)

```bash
git clone https://github.com/Uzair4264/ProofForge-AI.git
cd ProofForge-AI
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Unix: source .venv/bin/activate
pip install -e ".[dev]"
proofforge --help
```

The pipeline runs out of the box on the built-in **mock** backend (no model needed). For real inference, set up Ollama: see **[docs/setup_local_llm.md](docs/setup_local_llm.md)**.

> Upgrading from an older checkout? The CLI used to be `bbreport`; that name still works as an alias,
> and your existing config and sessions are picked up automatically.

## Quickstart

```bash
proofforge doctor                                   # verify environment
proofforge init --program hackerone:example-corp    # start a session
proofforge evidence add -f request.txt  -t http_request
proofforge evidence add -f response.txt -t http_response
proofforge evidence add -f shot.png     -t screenshot
proofforge report new --vuln-class xss --subtype reflected
proofforge verify                                   # integrity (Gap 1)
proofforge check                                    # compliance (Gap 3)
proofforge render -o report.md                      # report.md + audit.jsonl + integrity_summary.json
proofforge audit verify audit.jsonl                 # confirm the log chain is intact
```

**Full real-world walkthrough** (OWASP Juice Shop DOM-XSS, captured in Burp, on the live local model):
**[docs/walkthrough_juiceshop_dom_xss.md](docs/walkthrough_juiceshop_dom_xss.md)**.

## Contributing

Open source, Apache-2.0, **open for contribution**. The highest-leverage contributions need **no Python**:

- **Add a vulnerability class** — a YAML template in `src/proofforge/vuln_classes/templates/` plus its
  inference prompts in `src/proofforge/prompts/`. The engine is class-agnostic.
- **Add a program rule pack** — a YAML file in `src/proofforge/program_packs/packs/`.
- Improve prompts, docs, or the Python core (orchestrator, inference, provenance).

Open an issue or pull request on GitHub. To report a vulnerability in ProofForge itself, please use
GitHub's private vulnerability reporting instead of a public issue.

## License

[Apache-2.0](LICENSE).
