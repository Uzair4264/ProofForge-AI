# ProofForge AI

> A local-first AI assistant that helps bug bounty researchers produce **evidence-backed,
> program-compliant** reports — and **refuses to fabricate**.

ProofForge reads the evidence you captured, infers what it can, **traces every claim back to the
evidence that supports it**, enforces the target program's policy, and renders a submission-ready
report — all on your machine. It is *not* a scanner, *not* an exploit generator, and *not* a
"the-AI-writes-it-for-you" tool.

**CLI:** `bbreport` · **Package:** `bbreport-assistant` · **License:** Apache-2.0 · **Status:** v0, all five
vuln classes live-validated end-to-end.

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
| Severity | guessed | **deterministic CVSS v3.1** |
| Privacy | sent to the cloud | **100% local by default** |
| Auditability | none | **hash-chained, tamper-evident log** |

## Status (v0)

- **5 vulnerability classes:** XSS, SSRF, IDOR, CSRF, SQLi — each a YAML template (no Python to add more).
- **Full 6-stage pipeline:** ingestion & classification → inference → adaptive elicitation → integrity
  verification → compliance enforcement → rendering.
- **Local LLM** via Ollama (`qwen2.5:3b-instruct-q4_K_M`), with an offline **mock** backend and an
  opt-in cloud backend behind the same interface.
- **Deterministic core:** CVSS v3.1, scope/field/forbidden-content checks, claim→evidence DAG,
  hash-chained audit log.
- **33 passing tests**, cross-platform (Linux/macOS/Windows).
- **Live-validated end-to-end** against OWASP Juice Shop (real DOM-XSS → compliant report).

See the workflow diagram in [diagram.md](diagram.md), the full design in [CLAUDE.md](CLAUDE.md), and
the vision/positioning in [PROJECT.md](PROJECT.md).

## How it works

```
Evidence (HTTP, screenshots, repro)  ─►  Ingest & classify  ─►  Infer fields (LLM)
   ─►  Confirm/elicit  ─►  Integrity (Gap 1)  ─►  Compliance (Gap 3)  ─►  report.md + audit.jsonl
```

Deterministic code decides where rules exist; the LLM is called only for narrow natural-language
sub-tasks (classification, field inference, claim verification) and is always **advisory** — you
confirm every value before it lands in the report.

## Install (development)

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Unix: source .venv/bin/activate
pip install -e ".[dev]"
bbreport --help
```

The pipeline runs out of the box on the built-in **mock** backend (no model needed — that's what the
tests use). For real inference, set up Ollama: see **[docs/setup_local_llm.md](docs/setup_local_llm.md)**
(`ollama pull qwen2.5:3b-instruct-q4_K_M`, then `bbreport config init --force` and `bbreport doctor`).

## Quickstart

```bash
bbreport doctor                                   # verify environment
bbreport init --program hackerone:example-corp    # start a session
bbreport evidence add -f request.txt  -t http_request
bbreport evidence add -f response.txt -t http_response
bbreport evidence add -f shot.png     -t screenshot
bbreport report new --vuln-class xss --subtype reflected
bbreport verify                                   # integrity (Gap 1)
bbreport check                                    # compliance (Gap 3)
bbreport render -o report.md                      # report.md + audit.jsonl + integrity_summary.json
bbreport audit verify audit.jsonl                 # confirm the log chain is intact
```

**Full real-world walkthrough** (OWASP Juice Shop DOM-XSS, captured in Burp, on the live local model):
**[docs/walkthrough_juiceshop_dom_xss.md](docs/walkthrough_juiceshop_dom_xss.md)**.

## Contributing

Open source, Apache-2.0, **open for contribution**. The highest-leverage contributions need **no Python**:

- **Add a vulnerability class** — drop a YAML template in `bbreport_assistant/vuln_classes/templates/`
  plus its inference prompts in `bbreport_assistant/prompts/`. The engine is class-agnostic.
- **Add a program rule pack** — a YAML file in `bbreport_assistant/program_packs/packs/`.
- Improve prompts, docs, or the Python core (orchestrator, inference, provenance).

A future **Claude Code plugin / vendor-neutral MCP server** direction is sketched in
[PLUGIN.md](PLUGIN.md) (parked until v0 is stable).

## License

[Apache-2.0](LICENSE). Documentation (PROJECT.md) is CC BY 4.0.
