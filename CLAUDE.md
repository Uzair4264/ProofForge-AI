# CLAUDE.md — Technical Specification

> This document is the technical reference for building the project. It is written for the developer (you) and any future contributors (human or AI assistants like Claude Code) who need to understand how the system is structured and why.

---

## 0. Implementation Status (Living)

> This section tracks what is actually built versus specified. The sections below (§1–§23) remain the authoritative *design*. Where the implementation deviates from the spec for good reason, it is noted here.

**As of 2026-06-30 — v0 implemented, and live-validated end-to-end against a real target.**

**Live validation milestone (2026-06-30):** drove a genuine **OWASP Juice Shop DOM-XSS** through the full pipeline against the **live local Ollama model** (`qwen2.5:3b-instruct-q4_K_M`): evidence captured in Burp (request/response/screenshot/repro) → fields inferred by the model → integrity verification → compliance enforcement → rendered `report.md`. The integrity layer correctly flagged that the HTTP response alone only *partially* supports the "executes" claim (the screenshot carries it — exactly right for DOM XSS), compliance passed (scope ✓, CVSS 6.1 Medium validated ✓), and the hash-chained audit log verified intact. New artifacts from this work: `program_packs/packs/owasp_juiceshop.yaml` (program_id `owasp:juice-shop`, covers `localhost` + the public demo), `docs/setup_local_llm.md`, `docs/walkthrough_juiceshop_dom_xss.md`. The `MockLLMBackend` now parses the real host/target from the evidence for the endpoint field so offline dry-runs reflect the actual target. Note: `evidence/` (real captures + generated outputs) and `examples/` are git-ignored.

**Done:**
- Full package skeleton under `bbreport_assistant/` (the spec's §4.2 tree, folded under one import package). Console script `bbreport`.
- All six pipeline stages wired end-to-end via `core/orchestrator.py`.
- **All five v0 vuln classes** ship as YAML templates and run through one generic engine: **XSS, SSRF, IDOR, CSRF, SQLi**.
- Deterministic layers complete: CVSS v3.1 calculator, compliance enforcer (scope/required-fields/forbidden-content/severity/disclosure), provenance DAG, hash-chained audit log + verifier.
- LLM layer: abstract backend, **`MockLLMBackend`** (offline/test default, keys off a `PROMPT_ID:` marker), **`OllamaBackend`** (live, pinned to `qwen2.5:3b-instruct-q4_K_M`), opt-in OpenAI-compatible stub, and a hash-keyed cache.
- Inference engine (Stage 2), adaptive elicitation + batch confirmation (Stage 3), two renderers (`markdown_generic`, `hackerone_md`).
- CLI: `init`, `evidence`, `report`, `verify`, `check`, `render`, `session`, `config`, `doctor`, `audit`, `help`.
- Three program packs: `hackerone:example-corp`, `hackerone:generic`, `bugcrowd:generic`.
- **33 tests passing** (CVSS, audit chain, provenance, enforcer, inference, per-class template validation, parametrized end-to-end pipeline across all 5 classes).

**Implementation conventions / deviations (authoritative for contributors):**
- **Import package** is `bbreport_assistant/` (snake_case); distribution name stays `bbreport-assistant`, CLI stays `bbreport`. The spec's §4.2 packages live under it. `prompts/` lives *inside* the package for install portability.
- **Canonical field ids:** every vuln-class template MUST keep `affected_endpoint` (primary URL — used by the scope check) and `impact_description` (`long_text`, `mode: suggest_only`). All other fields are class-specific. The claim engine (`vuln_classes/engine.py`) and both renderers are class-agnostic and rely on this convention; do not re-hardcode per-class field ids.
- **Prompt marker:** every file in `bbreport_assistant/prompts/*.txt` starts with `PROMPT_ID: <id>` so `MockLLMBackend` can recognize it. Literal `{` / `}` in a prompt must be doubled (`str.format` rendering).
- **Adding a vuln class is now pure data:** template YAML + inference prompt files + one canned `MockLLMBackend` entry per new prompt id. `tests/test_templates.py` enforces these rules.
- **`platformdirs` uses `appauthor=False`** to avoid Windows `Author\AppName` double-nesting, matching the §4.2 single-directory layout.
- CLI default config is `mock` for offline use; switch `llm.backend: ollama` for live inference.

**Next steps (near-term, in order):**
1. **Pull the model and exercise live inference manually:** `ollama pull qwen2.5:3b-instruct-q4_K_M`, set `llm.backend: ollama`, run `bbreport doctor`, then drive a real report per vuln class against genuine evidence. Tune prompts/thresholds from observed model behavior.
2. Build the public test corpus (§15.2): 20–30 public HackerOne hacktivity disclosures; measure inference precision/recall (§15.5) and add red-team adversarial cases (§15.4).
3. Add golden + adversarial tests per vuln class (§13.5).
4. Then proceed to the v0.2+ roadmap in §19.

---

## 1. Project Identity

**Working name:** (`ProofForge AI`) thats the name i decided

**One-sentence definition:**
An open-source, local-first AI assistant that helps bug bounty researchers produce reports that are evidence-backed, program-compliant, and accepted faster by guiding them through structured submission and enforcing claim-to-evidence integrity before submission.

**What it is NOT:**
- Not a vulnerability scanner
- Not an exploit generator
- Not a replacement for the researcher's judgment
- Not a cloud SaaS product
- Not a polished AI-writes-it-for-you tool

**Design philosophy:**
- Deterministic code makes decisions where rules exist; the LLM is called only where natural-language understanding is required
- Real evidence is mandatory input; the tool refuses to fabricate
- **Evidence first, then questions.** The tool reads evidence and infers field values before asking the user anything. The user confirms or fills gaps.
- Local by default; cloud is opt-in for explicitly non-sensitive operations
- Auditable: every decision is logged
- Pluggable: vuln classes, program rules, severity frameworks, output formats, and LLM backends are all swappable modules
- **Vuln classes are data, not code.** New vulnerability classes are added by writing YAML templates, not Python
- **Cross-platform from day one.** The tool runs natively on Linux, macOS, and Windows. Achieved through Python + Ollama, both of which support all three platforms

---

## 2. Problem Statement (Technical Framing)

A bug bounty report is structurally a set of **claims** backed by **evidence**, conforming to **program-specific rules**. Bad reports fail because:

1. Claims are not backed by sufficient evidence (orphan claims)
2. Evidence does not actually support the claim (misrepresentation)
3. The report violates the target program's policy (out of scope, missing fields, forbidden content)
4. Severity is calculated incorrectly
5. The format does not serve the dual audience of triager and developer

A separate problem is that newcomer researchers often cannot answer expert-level structured questions until they've reviewed their evidence and learned the relevant vocabulary. Tools that demand expert vocabulary upfront either intimidate newcomers or invite guessing.

The tool addresses all six issues through three architectural layers, grounded in research on agentic AI security:

- **Inference Layer:** reads evidence first and pre-fills field values where possible, so the user is asked only what cannot be confidently inferred
- **Integrity Layer (Gap 1 — Action-Level Reasoning):** tracks the provenance of every claim back to its supporting evidence, detects orphans, misrepresentations, contradictions, and over-reach
- **Compliance Layer (Gap 3 — Domain-Specific Supervision):** enforces program-specific rules (scope, required fields, severity framework, forbidden content) using per-program rule packs

---

## 3. Conceptual Foundations

### 3.1 Gap 1: Action-Level Reasoning Applied to Report Integrity

In agentic AI security, Gap 1 refers to supervising the *trajectory* of an agent rather than filtering individual actions. The same concept is applied here at the *report* level:

- Every piece of evidence is an input with provenance metadata (source, type, hash, timestamp, sensitivity)
- Every claim in the report depends on one or more evidence items
- A directed acyclic graph (DAG) tracks claim-to-evidence dependencies
- The supervisor (the tool itself) validates the DAG continuously:
  - No claim may be orphaned (no supporting evidence)
  - No claim may contradict its own evidence
  - No claim may extrapolate substantially beyond what the evidence demonstrates
  - Cross-claim contradictions referencing the same evidence are flagged

### 3.2 Gap 3: Domain-Specific Supervision Applied to Bug Bounty Programs

In agentic AI security, Gap 3 refers to enforcing rules from a specific regulated domain (HIPAA, GDPR, PCI-DSS, etc.) on agent behavior. Here, each **bug bounty program** is treated as its own micro-regulatory regime:

- Each supported program is encoded as a **rule pack** (a YAML file)
- The rule pack defines scope, required fields, severity framework, forbidden content, disclosure rules, and output format preferences
- Before a report is finalized, it is checked against the loaded rule pack
- Every check is recorded in an audit log

### 3.3 Adaptive Elicitation Through Evidence-First Inference

The tool operates on a single unified workflow that adapts to the user's expertise rather than offering separate "expert" and "beginner" modes. The pattern:

1. The user uploads evidence before being asked questions
2. The tool's **inference engine** reads the evidence and pre-fills every field it can determine with confidence above a threshold
3. The elicitation step asks the user only about fields that could not be inferred, and presents inferred fields for confirmation
4. For any field, the user can ask for help, see examples, or say "I don't know" — all are first-class responses
5. Free-form prose is reserved for narrative fields (impact, remediation), not control flow

This design serves both newcomers (who don't have to know the vocabulary upfront) and experienced researchers (who blow through pre-filled fields with rapid confirmation) using the same code path.

### 3.4 Separation of Concerns

| Concern | Where it lives | Driven by |
|---|---|---|
| Which questions to ask the researcher | Elicitation engine | Vuln class template + program required fields |
| Which field values to infer from evidence | Inference engine | Vuln class template's `inference` blocks |
| Whether evidence backs a claim | Integrity layer (Gap 1) | LLM verification + deterministic rules |
| Whether the report meets program rules | Compliance layer (Gap 3) | Program rule pack (YAML) |
| How to format the output | Renderer module | Output format template |
| Severity computation | Severity framework module | CVSS v3.1 formula (deterministic) |

**Vulnerability class** drives elicitation, inference, and verification focus. **Program policy** drives compliance enforcement. These two axes are independent and must not be conflated in the architecture.

### 3.5 Structured Commands Beat Free-Form Conversation

The tool exposes structured CLI commands rather than a free-form chat interface. Reasoning:

- LLMs are more reliable on narrow, well-defined tasks than on workflow control
- Structured commands are scriptable, testable, and documentable
- Each command's behavior is reproducible given the same inputs
- Contributors can write tests for specific commands; they cannot easily test "what the LLM does when asked about XSS"

Within each command, the LLM is invoked for specific narrow sub-tasks (field inference, claim verification, prose polish). The LLM does not drive the overall workflow.

---

## 4. System Architecture

### 4.1 High-Level Flow

```
┌──────────────────────────────────────────────────────────┐
│ INPUT                                                    │
│ • Raw evidence (HTTP traffic, screenshots, code, repro)  │
│ • Target program ID                                      │
│ • Researcher's initial vulnerability description         │
└────────────────────┬─────────────────────────────────────┘
                     ▼
┌──────────────────────────────────────────────────────────┐
│ STAGE 1: INGESTION & CLASSIFICATION                      │
│ • Parse evidence files into structured Evidence objects  │
│ • Assign provenance metadata (ID, hash, sensitivity)     │
│ • LLM classifies vulnerability class                     │
│ • Load program rule pack and vuln-class template         │
└────────────────────┬─────────────────────────────────────┘
                     ▼
┌──────────────────────────────────────────────────────────┐
│ STAGE 2: INFERENCE ENGINE  ← evidence-first design       │
│ • Walk every field in the vuln class template            │
│ • For fields with `inference` blocks, query the LLM      │
│   with relevant evidence                                  │
│ • Record inferred value + confidence per field           │
│ • Cache results by hash(evidence + prompt)               │
└────────────────────┬─────────────────────────────────────┘
                     ▼
┌──────────────────────────────────────────────────────────┐
│ STAGE 3: ADAPTIVE ELICITATION                            │
│ • Present inferred fields for batch confirmation         │
│ • Ask user only about fields with no confident inference │
│ • Provide help, examples, "I don't know" as options      │
│ • Output: Claim objects linked to Evidence IDs           │
└────────────────────┬─────────────────────────────────────┘
                     ▼
┌──────────────────────────────────────────────────────────┐
│ STAGE 4: INTEGRITY VERIFICATION  ← Gap 1 enforcement     │
│ • Build claim-to-evidence DAG                            │
│ • Detect orphan claims (rule-based)                      │
│ • Verify claim-evidence consistency (LLM)                │
│ • Detect over-reach / contradictions (LLM)               │
│ • Block or escalate failures                             │
└────────────────────┬─────────────────────────────────────┘
                     ▼
┌──────────────────────────────────────────────────────────┐
│ STAGE 5: COMPLIANCE ENFORCEMENT  ← Gap 3 enforcement     │
│ • Scope check (deterministic)                            │
│ • Required field presence check (deterministic)          │
│ • Forbidden content scan (regex + LLM)                   │
│ • Severity recalculation/validation (deterministic)      │
│ • Disclosure rule check                                  │
└────────────────────┬─────────────────────────────────────┘
                     ▼
┌──────────────────────────────────────────────────────────┐
│ STAGE 6: RENDERING                                       │
│ • Apply program-preferred output template                │
│ • Produce dual-audience structure (triager + developer)  │
│ • Embed evidence references with stable IDs              │
└────────────────────┬─────────────────────────────────────┘
                     ▼
┌──────────────────────────────────────────────────────────┐
│ OUTPUT                                                   │
│ • report.md (or program-specific format)                 │
│ • audit_log.jsonl (signed, immutable)                    │
│ • integrity_summary.json (claims, evidence, links)       │
└──────────────────────────────────────────────────────────┘
```

### 4.2 Directory Structure

```
bbreport-assistant/
├── core/
│   ├── __init__.py
│   ├── orchestrator.py          # Main pipeline controller
│   ├── types.py                 # Shared dataclasses (Evidence, Claim, Field, Report)
│   └── exceptions.py
├── llm_backends/
│   ├── __init__.py
│   ├── base.py                  # Abstract LLM interface
│   ├── ollama_backend.py        # Local Ollama (default)
│   ├── openai_compatible.py     # For Groq, OpenAI, etc. (opt-in)
│   └── mock_backend.py          # For testing
├── evidence/
│   ├── __init__.py
│   ├── ingester.py              # File parsers (HTTP, image, text)
│   ├── provenance.py            # Provenance graph and integrity checks
│   ├── verifier.py              # LLM-backed claim verification
│   └── parsers/
│       ├── http_parser.py       # Burp/HAR/cURL parser
│       ├── image_parser.py      # Screenshot handler
│       └── text_parser.py       # Plain repro steps
├── inference/                   # NEW — Stage 2 (Inference Engine)
│   ├── __init__.py
│   ├── engine.py                # Walks template, drives per-field inference
│   ├── prompts.py               # Inference prompt templates
│   └── confidence.py            # Confidence scoring and thresholds
├── vuln_classes/                # Now mostly DATA, not Python
│   ├── __init__.py
│   ├── loader.py                # Loads YAML templates, validates schema
│   ├── schema.py                # Pydantic schema for vuln class templates
│   ├── engine.py                # Generic elicitation engine that reads templates
│   └── templates/               # The actual vuln class definitions
│       ├── xss.yaml
│       ├── ssrf.yaml
│       ├── idor.yaml
│       ├── csrf.yaml
│       └── sqli.yaml
├── program_packs/
│   ├── __init__.py
│   ├── loader.py                # Loads YAML rule packs
│   ├── schema.py                # Pydantic schema for rule packs
│   ├── enforcer.py              # Runs compliance checks
│   └── packs/
│       ├── hackerone_generic.yaml
│       ├── hackerone_example_program.yaml
│       └── bugcrowd_generic.yaml
├── severity_frameworks/
│   ├── __init__.py
│   ├── base.py
│   ├── cvss_v31.py              # CVSS v3.1 calculator
│   └── (cvss_v4.py, vrt.py — later)
├── output_formats/
│   ├── __init__.py
│   ├── base.py
│   ├── markdown_generic.py
│   ├── hackerone_md.py
│   └── templates/
├── elicitation/
│   ├── __init__.py
│   ├── dialog.py                # CLI Q&A flow with help/examples support
│   └── confirmation.py          # Batch-confirmation UI for inferred fields
├── audit/
│   ├── __init__.py
│   ├── logger.py                # Append-only signed log
│   └── chain.py                 # Hash chaining for tamper evidence
├── cli/
│   ├── __init__.py
│   ├── main.py                  # CLI entrypoint (uses click or typer)
│   └── commands/                # One file per command group
│       ├── init.py
│       ├── evidence.py
│       ├── report.py            # The vuln-class-specific commands live here
│       ├── verify.py
│       ├── check.py
│       └── render.py
├── prompts/
│   ├── classify_vuln.txt
│   ├── verify_claim.txt
│   ├── detect_overreach.txt
│   ├── infer_xss_context.txt
│   ├── infer_ssrf_target.txt
│   └── ...
├── tests/
│   ├── fixtures/                # Sample evidence files
│   ├── corpus/                  # Public HackerOne hacktivity samples
│   ├── test_provenance.py
│   ├── test_enforcer.py
│   ├── test_inference.py
│   └── ...
├── docs/
│   ├── architecture.md
│   ├── adding_a_program.md
│   ├── adding_a_vuln_class.md   # Critical contributor doc
│   ├── prompt_design.md
│   └── command_reference.md
├── pyproject.toml
├── README.md
├── CONTRIBUTING.md
├── LICENSE                      # Apache 2.0
├── CLAUDE.md                    # This file
├── PROJECT.md                   # Non-technical project doc
└── PLUGIN.md                    # Parked future variant (Claude Code plugin / MCP server)
```

**Runtime data locations (not hardcoded; resolved per OS via `platformdirs`):**

| Purpose | Linux | macOS | Windows |
|---|---|---|---|
| Config | `~/.config/bbreport-assistant/` | `~/Library/Application Support/bbreport-assistant/` | `%APPDATA%\bbreport-assistant\` |
| Sessions/Data | `~/.local/share/bbreport-assistant/` | `~/Library/Application Support/bbreport-assistant/` | `%LOCALAPPDATA%\bbreport-assistant\` |
| Cache | `~/.cache/bbreport-assistant/` | `~/Library/Caches/bbreport-assistant/` | `%LOCALAPPDATA%\bbreport-assistant\cache\` |

Resolved in code as:
```python
from platformdirs import user_config_dir, user_data_dir, user_cache_dir
CONFIG_DIR = Path(user_config_dir("bbreport-assistant"))
DATA_DIR   = Path(user_data_dir("bbreport-assistant"))
CACHE_DIR  = Path(user_cache_dir("bbreport-assistant"))
```

Never hardcode `~/.bbreport-assistant/` or similar; always go through `platformdirs`. This is a contributor discipline issue with cross-platform consequences.

### 4.3 Module Responsibilities

**`core/orchestrator.py`** — The pipeline controller. Reads config, loads program pack and vuln class template, drives stages 1-6 in order, handles errors. Has no domain logic itself.

**`core/types.py`** — All shared dataclasses. The `Evidence`, `Claim`, `Field`, `ProvenanceLink`, `Report`, `AuditEntry` types live here. Use Pydantic models for serialization.

**`llm_backends/base.py`** — Defines `LLMBackend` abstract class with one method: `complete(prompt: str, expected_format: Optional[Type]) -> str | dict`. All backends conform to this. Backends never know what they're being asked.

**`evidence/provenance.py`** — The DAG implementation. Nodes are evidence and claim objects. Edges are provenance links. Provides queries: `is_orphan(claim)`, `evidence_for(claim)`, `claims_using(evidence)`, `cycle_check()`.

**`evidence/verifier.py`** — Where LLM is called for integrity. Each function returns a structured verdict, never freeform text.

**`inference/engine.py`** — Reads a vuln class template, walks every field with an `inference` block, calls the LLM with relevant evidence, records inferred value + confidence. Output feeds into the elicitation stage.

**`inference/confidence.py`** — Thresholding logic. A field is considered "confidently inferred" if confidence ≥ threshold (default 0.7). Below threshold, the field is presented as a question to the user.

**`vuln_classes/loader.py`** — Loads YAML templates from `vuln_classes/templates/`, validates against the schema, exposes them by ID.

**`vuln_classes/engine.py`** — Generic engine that consumes a vuln class template + inferred field values + user inputs and produces a structured set of Claims. The same engine runs all vuln classes; the differences live in the YAML.

**`program_packs/enforcer.py`** — Runs compliance checks. Each check is a small function with signature `check(report: Report, pack: RulePack) -> CheckResult`. The enforcer runs them all and aggregates results.

**`elicitation/dialog.py`** — The user-facing Q&A. Reads pending fields (those not confidently inferred), asks the user, supports `?` (help), `examples`, `skip`, `unknown` as first-class responses.

**`elicitation/confirmation.py`** — The batch-confirmation UI. Presents all inferred fields with their values and confidence levels; the user confirms in bulk or drills into specific fields to edit.

**`output_formats/<format>.py`** — Each format module exposes a `render(report: Report) -> str` function. Templates live as text files in `templates/`.

---

## 5. Core Data Structures

### 5.1 Evidence

```python
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

class EvidenceType(Enum):
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    SCREENSHOT = "screenshot"
    CODE_SNIPPET = "code_snippet"
    REPRO_STEPS = "repro_steps"
    VIDEO = "video"
    LOG_OUTPUT = "log_output"

class SensitivityLevel(Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"   # contains PoC details
    RESTRICTED = "restricted" # contains PII or secrets

@dataclass
class Evidence:
    id: str                       # e.g., "ev-001"
    type: EvidenceType
    source_path: Path
    content_hash: str             # SHA-256 of the content
    sensitivity: SensitivityLevel
    extracted_text: Optional[str] # for searchable content
    metadata: dict                # parser-specific (e.g., HTTP method, URL)
    captured_at: Optional[datetime]
    notes: Optional[str]
```

### 5.2 Field (New — Reflects Adaptive Elicitation)

```python
class FieldState(Enum):
    NOT_YET_PROCESSED = "pending"
    INFERRED = "inferred"          # value set by inference engine
    CONFIRMED = "confirmed"        # user accepted the inferred value
    USER_PROVIDED = "user_provided" # user typed it directly
    SKIPPED = "skipped"            # user explicitly skipped (with warning)
    UNKNOWN = "unknown"            # user said "I don't know"

@dataclass
class Field:
    id: str                       # e.g., "rendering_context"
    label: str                    # display name
    field_type: str               # "url", "choice", "long_text", etc.
    value: Optional[any]          # current value (None if not set)
    state: FieldState
    confidence: Optional[float]   # 0.0-1.0, set when state == INFERRED
    inference_reasoning: Optional[str]   # why the engine inferred this
    is_required: bool
```

### 5.3 Claim

```python
class ClaimCategory(Enum):
    VULNERABILITY_ASSERTION = "vuln_assertion"     # "X is vulnerable to Y"
    IMPACT_ASSERTION = "impact_assertion"           # "An attacker can do Z"
    REPRODUCTION = "reproduction"                   # "Steps to reproduce..."
    SEVERITY_JUSTIFICATION = "severity_just"        # "This is High because..."
    REMEDIATION = "remediation"                     # "To fix this..."

@dataclass
class Claim:
    id: str                       # e.g., "claim-A"
    category: ClaimCategory
    text: str
    evidence_ids: list[str]       # references to Evidence.id
    author: str                   # "user", "inferred", "llm_polished"
    confidence: Optional[float]   # for inferred or LLM-generated claims
```

### 5.4 Provenance Link

```python
@dataclass
class ProvenanceLink:
    claim_id: str
    evidence_id: str
    relation: str                 # "supports", "demonstrates", "contradicts"
    verified: bool                # has the LLM verifier confirmed?
    verifier_notes: Optional[str]
```

### 5.5 Rule Pack

```yaml
# program_packs/packs/hackerone_example_program.yaml
program_id: "hackerone:example-corp"
program_name: "Example Corp Security Program"
platform: "hackerone"
last_updated: "2026-01-15"
source_url: "https://hackerone.com/example-corp"

scope:
  in_scope_assets:
    - "*.example.com"
    - "api.example.com"
    - "mobile-app:com.example.app"
  out_of_scope_assets:
    - "blog.example.com"
    - "support.example.com"
  in_scope_vuln_types:
    - "xss"
    - "sqli"
    - "ssrf"
    - "idor"
    - "csrf"
    - "rce"
    - "auth_bypass"
  out_of_scope_vuln_types:
    - "self_xss"
    - "missing_security_headers_no_impact"
    - "rate_limiting"
    - "clickjacking_no_sensitive_action"

required_fields:
  - "vulnerability_title"
  - "affected_endpoint"
  - "vulnerability_description"
  - "reproduction_steps"
  - "impact_demonstration"
  - "severity_rating"
  - "remediation_suggestion"

severity_framework: "cvss_v3.1"
severity_overrides: {}   # optional program-specific overrides

forbidden_content:
  patterns:
    - type: "regex"
      pattern: "[0-9]{3}-[0-9]{2}-[0-9]{4}"
      description: "Unredacted SSN"
    - type: "regex"
      pattern: "(?i)(password|api[_-]?key|secret)\\s*[=:]\\s*[\\w!@#$]+"
      description: "Hardcoded secret in evidence"
  llm_checks:
    - "Does the report contain unredacted personally identifiable information of real users?"
    - "Does the report contain raw automated scanner output (Burp Scanner, Nuclei JSON dumps, etc.)?"

disclosure_rules:
  embargo_days: 90
  public_disclosure_requires_approval: true
  must_include_disclosure_statement: false

output_preferences:
  format: "hackerone_md"
  include_cvss_vector: true
  include_screenshots: "inline"
```

### 5.6 Vuln Class Template (New — Replaces Hand-Coded Vuln Class Modules)

This is the canonical example. Adding a new vuln class means writing a YAML file like this.

```yaml
# vuln_classes/templates/xss.yaml
vuln_class: xss
display_name: "Cross-Site Scripting"
cwe: CWE-79
subtypes:
  - reflected
  - stored
  - dom_based

required_fields:
  - id: affected_endpoint
    label: "Affected endpoint URL"
    field_type: url
    validation: valid_url
    inference:
      from_evidence: [http_request]
      llm_prompt: "infer_endpoint_from_request"
      confidence_threshold: 0.8
    help:
      short: "The URL where the XSS occurs"
      long: |
        Provide the full URL including the path and any query parameters.
        Example: https://example.com/search?q=
      examples:
        - "https://example.com/search?q="
        - "https://example.com/profile/edit"

  - id: injection_vector
    label: "Injection vector"
    field_type: choice
    options: [url_param, form_field, header, cookie, path, other]
    inference:
      from_evidence: [http_request, http_response]
      llm_prompt: "infer_xss_vector"
      confidence_threshold: 0.7
    help:
      short: "Where is the payload injected?"
      long: |
        XSS payloads can be injected via different parts of the request:
        - url_param: a query string parameter (?q=payload)
        - form_field: a form input value
        - header: an HTTP header (User-Agent, Referer, etc.)
        - cookie: a cookie value
        - path: a path component (/foo/payload)

  - id: payload
    label: "Payload used"
    field_type: string
    validation: non_empty
    inference:
      from_evidence: [http_request, http_response]
      llm_prompt: "extract_xss_payload"
      confidence_threshold: 0.85

  - id: rendering_context
    label: "Rendering context"
    field_type: choice
    options: [html_body, html_attribute, script_block, style_block, url_context, other]
    inference:
      from_evidence: [http_response]
      llm_prompt: "infer_xss_context"
      confidence_threshold: 0.7
    help:
      short: "Where in the response is your payload rendered?"
      long: |
        XSS payloads execute differently depending on context:
        - html_body: rendered between HTML tags (<div>payload</div>)
        - html_attribute: rendered inside an attribute (<a href="payload">)
        - script_block: rendered inside a <script> tag
        - style_block: rendered inside a <style> tag
        - url_context: rendered as a URL (href, src, etc.)
        Don't guess — check the actual response.
      examples:
        - "Saw <div>my payload</div> in response → html_body"
        - "Saw <a href='my payload'> → html_attribute"

  - id: impact_description
    label: "Impact description"
    field_type: long_text
    editor: true
    inference:
      # Free-text fields can have inference too — generates a suggested draft
      from_evidence: [http_request, http_response, screenshot]
      llm_prompt: "draft_xss_impact"
      confidence_threshold: 0.0   # always show as draft, user always reviews
      mode: suggest_only          # never auto-fill; always present as suggestion
    help:
      short: "What can an attacker do with this XSS?"
      long: |
        Describe what an attacker achieves with this vulnerability.
        Be specific to what your evidence demonstrates — don't claim
        impacts you haven't proven.
        Common XSS impacts:
        - Session theft (only if HttpOnly is absent — demonstrate it)
        - Phishing via injected content
        - Actions on behalf of the user (only if shown in evidence)

required_evidence:
  - type: http_request
    description: "Request demonstrating the injection"
    required: true
  - type: http_response
    description: "Response showing the payload rendered"
    required: true
  - type: screenshot
    description: "Screenshot of execution (alert, exfiltration, etc.)"
    required: false
    note: "Strongly recommended for visual proof"

severity_hints:
  default_cvss_v31: "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
  notes: |
    Common adjustments:
    - UI:N if no user interaction is required (rare for reflected XSS)
    - PR:L or PR:H if authentication is needed to reach the injection
    - S:U if the XSS does not break out of its origin scope
    - C:H/I:H if you actually demonstrate session theft or account takeover

verifier_focus:
  - "Confirm the response actually contains the payload in an executable context"
  - "Confirm the impact claim matches the demonstrated execution"
  - "Flag if impact claims session theft without a cookie-exfiltration PoC"
```

### 5.7 Audit Entry

```python
@dataclass
class AuditEntry:
    sequence: int                 # monotonically increasing
    timestamp: datetime
    previous_hash: str            # SHA-256 of previous entry
    entry_hash: str               # SHA-256 of this entry's content
    actor: str                    # "system", "user", "llm", "inference"
    action: str                   # what happened
    target: str                   # what was acted on
    result: str                   # outcome
    details: dict                 # structured context
```

---

## 6. Vulnerability Classes (v0 Set)

The v0 ships with five vuln classes, each as a YAML template (see §5.6 for the canonical XSS example). The templates encode required fields, inference rules, help text, required evidence, severity hints, and verifier focus areas.

### 6.1 XSS (Cross-Site Scripting) — CWE-79

**Subtypes:** Reflected, Stored, DOM-based
**Required evidence:**
- HTTP request containing the injection point
- HTTP response showing the payload rendered/executed
- Screenshot of execution (alert, exfiltration, or visible effect)
- Identification of the sink (URL parameter, form field, header, etc.)

**Inference targets:** endpoint, vector, payload, rendering context, suggested impact draft

**Verifier focus:** Confirm the response actually contains the unescaped payload in an executable context; confirm impact claims match the demonstrated execution.

### 6.2 SSRF (Server-Side Request Forgery) — CWE-918

**Subtypes:** Basic SSRF, blind SSRF, SSRF-to-internal-services
**Required evidence:**
- HTTP request showing the SSRF trigger
- Response or out-of-band evidence (DNS callback, internal service response)
- Identification of the parser/component being abused
- Demonstrated internal reach (metadata endpoint, internal IP, etc.) if claimed

**Inference targets:** vulnerable parameter, target URL/host, internal reach assertion, authentication context

**Verifier focus:** Confirm response demonstrates server-side fetch behavior; confirm any "internal access" claim is backed by actual evidence of internal reach (not just claimed).

### 6.3 IDOR (Insecure Direct Object Reference) — CWE-639

**Required evidence:**
- HTTP request demonstrating access to a resource the authenticated user shouldn't have
- Evidence of the authorization context (which user, what session)
- Evidence that the resource belongs to a different user/scope
- Reproduction with two different user accounts where applicable

**Inference targets:** affected endpoint, object identifier pattern, authorization mechanism

**Verifier focus:** Confirm the two requests are made by different users; confirm the accessed data actually belongs to a different scope.

### 6.4 CSRF (Cross-Site Request Forgery) — CWE-352

**Required evidence:**
- HTML/JS PoC that triggers the action without legitimate user intent
- Demonstration that the action succeeds (state change, money transfer, etc.)
- Evidence of absent or bypassable CSRF protection (no token, predictable token, missing SameSite, etc.)
- Identification of why the action is security-sensitive

**Inference targets:** target endpoint, action type, state-change confirmation, protection mechanism status

**Verifier focus:** Confirm the PoC actually triggers cross-origin; confirm the action is state-changing (not just reading); confirm protections are genuinely absent.

### 6.5 SQLi (SQL Injection) — CWE-89

**Subtypes:** Error-based, blind boolean, blind time-based, UNION-based
**Required evidence:**
- HTTP request showing the injection point
- Response demonstrating SQL behavior (error, conditional response, timing difference, extracted data)
- Identification of the database or behavior signature
- Demonstration of impact (data extraction, auth bypass, etc.)

**Inference targets:** injection point, SQLi subtype, database fingerprint, impact category

**Verifier focus:** Confirm the response shows database behavior, not just generic error; confirm extracted data is real, not echoed back from input.

---

## 7. The LLM Integration Layer

### 7.1 Default Backend Configuration

```python
# Default config
DEFAULT_BACKEND = "ollama"
DEFAULT_MODEL = "qwen2.5:3b-instruct-q4_K_M"   # adjustable in user config
DEFAULT_ENDPOINT = "http://localhost:11434"
TEMPERATURE = 0.1                              # low for deterministic-ish output
MAX_TOKENS = 1024
TIMEOUT_SECONDS = 120
```

For users with better hardware, the config supports:
```yaml
# ~/.bbreport-assistant/config.yaml
llm:
  backend: "ollama"
  model: "qwen2.5:14b-instruct-q4_K_M"  # for users with 16GB+ RAM
  endpoint: "http://localhost:11434"
  temperature: 0.1
```

### 7.2 Roles the LLM Plays

The LLM is called for five distinct purposes:

1. **Vulnerability classification** (Stage 1) — given evidence + user description, classify the vuln class
2. **Field inference** (Stage 2) — for each field in the template with an `inference` block, infer the value from relevant evidence
3. **Claim-evidence verification** (Stage 4) — for each claim, verify the linked evidence actually supports it
4. **Over-reach detection** (Stage 4) — flag claims that extrapolate beyond what evidence demonstrates
5. **Forbidden content semantic checks** (Stage 5) — for content that regex can't catch

Each role has its own prompt template stored in `prompts/`.

### 7.3 Prompt Design Principles

1. **Always request structured output.** JSON with a defined schema, not freeform prose.
2. **Always include role + task + input + output format + examples.** No shortcuts.
3. **Always include a "if uncertain" clause.** The model must be allowed to say "I don't know."
4. **Always reject ambiguous outputs.** If the model returns invalid JSON, retry once, then raise.
5. **Never trust the model's reasoning blindly.** All LLM verdicts are advisory; the human researcher confirms.

### 7.4 Example Prompt: Field Inference (XSS Rendering Context)

```
You are an evidence analyzer for bug bounty reports.

Your task: determine the HTML rendering context in which an XSS payload is reflected, based on the HTTP response below.

PAYLOAD: {payload}
HTTP RESPONSE (truncated to relevant section):
{response_snippet}

Possible contexts:
- html_body: payload appears between HTML tags (e.g., <div>PAYLOAD</div>)
- html_attribute: payload appears inside an HTML attribute (e.g., <a href="PAYLOAD">)
- script_block: payload appears inside a <script> tag
- style_block: payload appears inside a <style> tag
- url_context: payload appears as a URL value (href, src, action)
- other: anything else
- uncertain: if you cannot determine with reasonable confidence

Respond with a JSON object only:
{
  "context": "<one of the above>",
  "confidence": <0.0 to 1.0>,
  "reasoning": "<one sentence explaining what you saw>"
}

Example:
Response: "<div class='result'>PAYLOAD</div>"
Output: {"context": "html_body", "confidence": 0.95, "reasoning": "Payload is between div tags"}
```

### 7.5 Example Prompt: Claim-Evidence Verification

```
You are an integrity checker for bug bounty reports. You determine whether a piece of evidence supports a stated claim.

CLAIM:
{claim_text}

EVIDENCE TYPE: {evidence_type}
EVIDENCE CONTENT:
{evidence_content}

Decide whether the evidence directly supports the claim. Be strict: the evidence must demonstrate the specific assertion in the claim, not merely be related to it.

Respond with a JSON object only:
{
  "supports": true | false | "partial",
  "confidence": <0.0 to 1.0>,
  "reasoning": "<one or two sentences>",
  "missing_for_full_support": "<what additional evidence would strengthen, if applicable>"
}
```

### 7.6 LLM Call Budget per Report

A typical report consumes:

- 1 call for vulnerability classification (Stage 1)
- 4–8 calls for field inference (Stage 2, depends on vuln class)
- 1 call per claim for verification (Stage 4, ~3–5 claims per report)
- 1 call for over-reach detection (Stage 4)
- 1 call for forbidden content semantic check (Stage 5)
- 0–1 call for remediation suggestion (optional, in template)

**Total: ~10–18 LLM calls per report.** On Qwen 2.5 3B running on 8 GB RAM, expect roughly 4–10 minutes total wall time. Slow but acceptable for a thoughtful report.

### 7.7 Caching

All LLM calls are cached by `hash(prompt + model + temperature)`. Re-running the same check returns cached results instantly. Cache lives in `~/.bbreport-assistant/cache/` and is opt-out-able via `--no-cache`.

Inference results are especially cache-friendly because the same evidence + same field rarely changes within a session.

---

## 8. The Inference Engine (Stage 2) — Detailed Specification

### 8.1 Purpose

After evidence is ingested and the vuln class is determined, the inference engine attempts to fill in as many template fields as possible by reading the evidence. This dramatically reduces the elicitation burden on the user and serves as the foundation for adaptive elicitation.

### 8.2 Algorithm

```
function run_inference(template, evidence_set):
    inferred_fields = {}
    for field in template.required_fields:
        if not field.inference:
            inferred_fields[field.id] = Field(state=PENDING)
            continue

        relevant_evidence = filter_evidence(
            evidence_set,
            types=field.inference.from_evidence
        )

        if not relevant_evidence:
            inferred_fields[field.id] = Field(state=PENDING)
            continue

        prompt = load_prompt(field.inference.llm_prompt)
        result = llm.complete(
            prompt=render(prompt, evidence=relevant_evidence, field=field),
            expected_format=InferenceResult
        )

        if result.confidence >= field.inference.confidence_threshold:
            inferred_fields[field.id] = Field(
                value=result.value,
                state=INFERRED,
                confidence=result.confidence,
                inference_reasoning=result.reasoning
            )
        else:
            inferred_fields[field.id] = Field(
                state=PENDING,
                inference_reasoning=f"Low-confidence inference: {result.value}"
            )

    return inferred_fields
```

### 8.3 Confidence Thresholds

Each field declares its own threshold in its `inference` block. Default 0.7. Some fields with high inference reliability (extracting a payload byte-for-byte) can use 0.85+. Some narrative fields use threshold 0.0 with `mode: suggest_only`, meaning the LLM produces a draft but it's always shown to the user for review rather than auto-accepted.

### 8.4 Parallelization

Independent field inferences (different prompts, different relevant evidence) can be run concurrently. This is the single biggest performance optimization in the system. On modest hardware, sequential inference for 8 fields might take 80 seconds; parallel might take 15–20 seconds (bounded by the slowest field plus model concurrency limits).

### 8.5 Failure Modes

- **LLM returns invalid JSON:** retry once; on second failure, mark field as PENDING and log
- **LLM returns "uncertain":** mark field as PENDING
- **Relevant evidence missing:** mark field as PENDING with a note about which evidence type is needed
- **Inference timeout:** mark field as PENDING; do not block the workflow

The inference engine never blocks the workflow. A failed inference simply means the user gets asked instead.

### 8.6 The Confirmation Step

After inference, the user sees a batch confirmation:

```
Based on your evidence, I've filled in the following:

  ✓ Affected endpoint: https://example.com/search?q=    [high confidence]
  ✓ Injection vector: URL parameter "q"                  [high confidence]
  ✓ Payload: <script>alert(1)</script>                   [high confidence]
  ? Rendering context: html_body                         [medium confidence]
    ↳ I saw your payload between <div> tags; this looks
      like HTML body context. Confirm? [Y/n/edit]

Confirm all high-confidence values? [Y/n]
```

The user can accept everything in bulk, edit specific fields, or reject inferences they disagree with. Rejected inferences fall back to the standard elicitation question.

---

## 9. The Integrity Layer (Gap 1) — Detailed Specification

### 9.1 Provenance Graph

Implemented as a DAG with:
- Nodes: Evidence and Claim objects (both inherit a `Node` mixin)
- Edges: ProvenanceLink objects, always Claim → Evidence direction
- Operations: add_node, add_link, query orphans, query unsupported, cycle detection (claims should not depend on other claims in v0; only on evidence)

### 9.2 Integrity Checks (in order of execution)

1. **Orphan check** (deterministic, fast)
   - For each Claim, assert `len(claim.evidence_ids) > 0`
   - Fail = hard block, user must add evidence or remove claim

2. **Evidence existence check** (deterministic, fast)
   - For each evidence_id in any claim, assert the Evidence exists in the graph
   - Fail = hard block, indicates programming error

3. **Hash integrity check** (deterministic, fast)
   - For each Evidence, recompute hash, compare to recorded
   - Fail = hard block, indicates evidence was tampered with after registration

4. **Claim-evidence consistency check** (LLM-backed, slow)
   - For each (claim, evidence) pair, ask the LLM whether the evidence supports the claim
   - Result: `supports`, `partial`, or `not_supports` + confidence
   - `not_supports` with high confidence = block; `partial` = warn user

5. **Over-reach detection** (LLM-backed, slow)
   - For each claim with category `IMPACT_ASSERTION` or `VULNERABILITY_ASSERTION`, the LLM is given all related evidence and asked: "does the evidence justify the *full scope* of this claim?"
   - Catches the "credentials can be stolen" claim backed only by metadata-retrieval evidence

6. **Cross-claim contradiction check** (LLM-backed, optional)
   - The LLM is given all claims and asked to identify contradictions
   - Used only if multiple claims share evidence

### 9.3 Failure Modes and User Recovery

When a check fails, the user has three options:
- **Provide more evidence** → re-run the check
- **Soften the claim** → modify the claim text and re-run
- **Override** (with audit log entry) → mark the check as user-acknowledged and proceed

Override requires explicit confirmation and is recorded with the override reason. Some checks (orphan, hash) cannot be overridden.

---

## 10. The Compliance Layer (Gap 3) — Detailed Specification

### 10.1 Rule Pack Loading

On startup:
1. Load all YAML files in `program_packs/packs/`
2. Validate each against the Pydantic schema
3. Index by `program_id`
4. The user selects a program via CLI: `bbreport init --program hackerone:example-corp`

### 10.2 Compliance Checks (in order of execution)

1. **Scope check** (deterministic)
   - Affected asset in `in_scope_assets`?
   - Vuln class in `in_scope_vuln_types`?
   - Fail = hard block

2. **Required fields check** (deterministic)
   - For each field in `required_fields`, assert the report has it
   - Fail = ask user to provide

3. **Forbidden content (regex)** (deterministic, fast)
   - Run all regex patterns over the assembled report text
   - Any match = warn user, suggest redaction

4. **Forbidden content (LLM)** (LLM-backed, slow)
   - Run LLM-based forbidden content checks from the rule pack
   - Result is advisory unless flagged "must_block"

5. **Severity validation** (deterministic)
   - Recompute severity using the configured framework (CVSS v3.1 for v0)
   - Compare to user's claimed severity
   - Mismatch = suggest correction

6. **Disclosure rule check** (deterministic)
   - If the report contains disclosure-statement requirements, verify they're present
   - Embargo dates inserted if required

### 10.3 Output of Compliance Stage

```python
@dataclass
class ComplianceReport:
    program_id: str
    checks_run: list[CheckResult]
    overall_status: Literal["pass", "warn", "block"]
    actionable_items: list[str]   # human-readable
```

This is included in the audit log and shown to the user before final rendering.

---

## 11. Audit Logging

### 11.1 Format

Append-only JSONL file. Each line is one AuditEntry. Each entry is hash-chained to the previous:

```
{"sequence": 0, "timestamp": "...", "previous_hash": "0000...", "entry_hash": "abc...", "actor": "system", "action": "session_start", ...}
{"sequence": 1, "timestamp": "...", "previous_hash": "abc...", "entry_hash": "def...", ...}
```

### 11.2 What Gets Logged

- Every evidence ingestion (with hash)
- Every LLM call (prompt hash + response hash, not full content unless verbose mode)
- Every inference result (field, value, confidence)
- Every user confirmation/rejection of inferred values
- Every integrity check result
- Every compliance check result
- Every user override
- Every report finalization

### 11.3 What Does NOT Get Logged

- Raw evidence content (privacy: stays in-session)
- Researcher's identifying information (privacy)
- Cloud API keys or credentials (security)

### 11.4 Verification Tool

A small companion command verifies the log chain: `bbreport audit verify <log_file>`. Walks the chain, recomputes hashes, reports any break.

---

## 12. CLI Design (v0)

### 12.1 Command Groups

```
bbreport init        — start a new report session
bbreport evidence    — manage evidence files
bbreport report      — work on the report itself (vuln-class-aware subcommands)
bbreport verify      — run integrity checks (Gap 1)
bbreport check       — run compliance checks (Gap 3)
bbreport render      — produce the final output
bbreport session     — manage sessions
bbreport config      — view/edit configuration
bbreport doctor      — diagnose setup issues
bbreport audit       — verify audit log integrity
bbreport help        — vuln-class help (e.g., bbreport help vuln-class ssrf)
```

### 12.2 Initialize a Session

```bash
bbreport init --program hackerone:example-corp
# Creates a new session directory and writes session metadata.
# The vuln class is determined later (after evidence is ingested),
# but can be set explicitly with --vuln-class.
```

### 12.3 Add Evidence

```bash
bbreport evidence add --file ./request.txt --type http_request
bbreport evidence add --file ./response.txt --type http_response
bbreport evidence add --file ./screenshot.png --type screenshot
bbreport evidence add --file ./repro.md --type repro_steps

bbreport evidence list    # show what's been added
bbreport evidence remove --id ev-002    # remove by ID
```

### 12.4 The Vuln-Class-Specific Report Commands

Each vulnerability class has its own subcommand under `report`. These trigger the appropriate template's elicitation flow.

```bash
bbreport report new --vuln-class xss --subtype reflected
bbreport report new --vuln-class ssrf --subtype blind
bbreport report new --vuln-class idor
bbreport report new --vuln-class csrf
bbreport report new --vuln-class sqli --subtype time-based
```

A user uncertain about the class can omit it; the tool will classify from evidence:

```bash
bbreport report new
# (tool runs classification, asks user to confirm)
```

### 12.5 Example Session: Newcomer User

```
$ bbreport init --program hackerone:example-corp
✓ Session created: ~/.bbreport-assistant/sessions/sess-2026-06-26-001

$ bbreport evidence add --file ./request.txt --type http_request
✓ Added ev-001 (http_request)
$ bbreport evidence add --file ./response.txt --type http_response
✓ Added ev-002 (http_response)
$ bbreport evidence add --file ./screenshot.png --type screenshot
✓ Added ev-003 (screenshot)

$ bbreport report new
Classifying vulnerability from evidence...
  → reflected XSS (confidence: 0.91)
Proceed with reflected XSS? [Y/n] y

Inferring fields from evidence...
  ✓ Affected endpoint: https://example.com/search?q=    [high]
  ✓ Injection vector: URL parameter "q"                  [high]
  ✓ Payload: <script>alert(1)</script>                   [high]
  ? Rendering context: html_body                         [medium]
    ↳ Saw payload between <div> tags. Confirm? [Y/n/?]
> y

I couldn't infer this field — please provide it:

Impact description (one or two sentences): [? for help]
> ?
  Describe what an attacker achieves with this vulnerability.
  Be specific to what your evidence demonstrates.
  Examples available with "examples".
> examples
  - "An attacker can execute arbitrary JavaScript in the victim's browser,
     allowing for session theft if HttpOnly is not set."
  - "Reflected XSS allows phishing by injecting fake login forms."
> The application's cookies don't have HttpOnly so I could steal session tokens.

  ⚠ Did you actually demonstrate cookie theft, or are you inferring?
   [demonstrated/inferred]
> inferred

  Got it. I'll mark this as a plausible impact, not demonstrated.

Suggested severity: AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (6.1, Medium)
Accept? [Y/edit/explain]
> y

$ bbreport verify
Running integrity checks...
  ✓ All claims have supporting evidence
  ⚠ Impact claim is partially inferred — added clarifying note
  ✓ No over-reach detected
  ✓ No contradictions detected

$ bbreport check
Running compliance checks against hackerone:example-corp...
  ✓ Asset in scope
  ✓ Vuln type in scope (XSS)
  ✓ All required fields present
  ✓ No forbidden content detected
  ✓ Severity uses program's framework
✓ All compliance checks passed.

$ bbreport render --output report.md
✓ Report written to: report.md
✓ Audit log: audit.jsonl
```

### 12.6 Example Session: Experienced User (Same Flow, Fast)

```
$ bbreport init --program hackerone:example-corp && \
  bbreport evidence add -f req.txt -t http_request && \
  bbreport evidence add -f res.txt -t http_response && \
  bbreport evidence add -f sc.png -t screenshot && \
  bbreport report new --vuln-class xss --subtype reflected

Inferring fields from evidence...
  ✓ All fields inferred at high confidence.
Confirm all? [Y/edit]
> y

Impact:
> stored XSS in user profile allows arbitrary JS execution in the context
of any user viewing the profile. Cookie exfil to attacker-controlled
server demonstrated in ev-003.

Severity AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N? [Y]
> y

$ bbreport verify && bbreport check && bbreport render --output report.md
✓ All checks passed. Report rendered.
```

### 12.7 Help Mode

```bash
bbreport help vuln-class ssrf
# Prints what the SSRF template needs: required fields, required evidence,
# common pitfalls, links to learning resources.

bbreport help vuln-class ssrf --subtype blind
# Subtype-specific guidance.

bbreport help command report
# Help for a CLI command.
```

### 12.8 Configuration File

`~/.bbreport-assistant/config.yaml`:
```yaml
llm:
  backend: ollama
  model: qwen2.5:3b-instruct-q4_K_M
  endpoint: http://localhost:11434
  temperature: 0.1

inference:
  enabled: true                # set false to skip Stage 2 entirely
  parallel: true               # run independent inferences concurrently
  cache: true

privacy:
  allow_cloud_backends: false
  cloud_only_for_non_sensitive: true

cache:
  enabled: true
  ttl_days: 30
```

### 12.9 The First-Class Responses

Within any elicitation prompt, the user can type:
- `?` — show short help for this field
- `??` or `help` — show long help with examples
- `examples` — show 2–3 example answers
- `skip` — defer this field (warning issued if required)
- `unknown` — explicitly say "I don't know"; tool offers low-confidence inference or accepts as unknown
- `back` — return to the previous field
- `cancel` — abort the report session

These are universally available; the user doesn't have to remember command-specific aliases.

---

## 13. Adding a New Vulnerability Class

This is the most common contributor task. The workflow:

1. **Pick a vuln class.** Check `vuln_classes/templates/` — if there's no YAML for it, you can add one.

2. **Read the canonical template** (`xss.yaml`) to understand the structure.

3. **Write the template.** Fields include:
   - `vuln_class` (snake_case identifier)
   - `display_name`, `cwe`, `subtypes`
   - `required_fields[]` — each with id, label, field_type, optional `inference`, `help`, `validation`, `examples`
   - `required_evidence[]` — what evidence types must accompany this vuln class
   - `severity_hints` — default CVSS vector and adjustment notes
   - `verifier_focus[]` — what the LLM verifier should pay special attention to for this class

4. **Write any new inference prompts** referenced by the template. Place them in `prompts/`. Each prompt must request structured JSON output matching the field's value schema.

5. **Add tests.** At minimum:
   - One golden test: a known public report of this vuln class; the tool should produce a similar structured report
   - One adversarial test: a thin or misleading description; the verifier should catch it

6. **Open a PR.** No Python required for most contributions. Reviewer focuses on: vocabulary accuracy, completeness of required evidence, inference prompt quality.

---

## 14. Adding a New Program Rule Pack

1. Copy `program_packs/packs/hackerone_generic.yaml` as a starting template.
2. Fill in `scope`, `required_fields`, `severity_framework`, `forbidden_content`, `disclosure_rules`, `output_preferences`.
3. Reference the program's public policy page in `source_url`.
4. Update `last_updated` whenever the program's policy changes.
5. Add the pack to the test corpus with at least one public report against this program.

---

## 15. Testing Strategy

### 15.1 Unit Tests

- Pure functions (severity calc, regex matching, hash chain, inference confidence thresholding) are unit tested in `tests/`
- Aim for >80% coverage on deterministic code
- LLM-dependent functions are tested with `MockLLMBackend` returning canned responses

### 15.2 Integration Tests

- A corpus of 20-30 public HackerOne hacktivity disclosures
- For each: ingest the public PoC, run the pipeline, compare output to the original report
- Track acceptance metrics: did the inference engine correctly extract fields? Did the integrity layer catch known issues? Did the compliance layer flag scope correctly?

### 15.3 Manual Evaluation

- A small set of "golden" report cases reviewed by a real bug bounty researcher
- Quarterly evaluation on a fresh batch of public reports

### 15.4 Red Team Evaluation

- Deliberately bad inputs: fabricated claims with no evidence, evidence that contradicts claims, out-of-scope targets, etc.
- The tool should catch all of these
- Tracked as a regression suite

### 15.5 Inference Quality Tracking

Specifically for the inference engine:
- A held-out set of (evidence, expected field values) pairs per vuln class
- Measure: precision (when the engine asserts a value, is it correct?), recall (what fraction of inferable fields does the engine actually fill?)
- Goal: high precision (≥0.95) over high recall. Wrong inferences are worse than missing ones, because they waste the user's trust.

---

## 16. Build, Package, and Distribution

### 16.1 Build System

- `pyproject.toml` with hatchling or setuptools
- Python 3.11+ required
- Dependencies kept minimal: `pydantic`, `httpx`, `click` (or `typer`), `pyyaml`, `pillow`, `cryptography`, `platformdirs`, `rich` (for cross-platform terminal output)

### 16.2 Supported Platforms

The tool runs natively on all three major desktop OSes. None is a second-class target.

| Platform | Support level | Notes |
|---|---|---|
| Linux (Ubuntu, Debian, Fedora, Arch, Kali, Parrot) | First-class | Primary dev environment for many security researchers |
| macOS (Intel and Apple Silicon) | First-class | Apple Silicon has a meaningful hardware advantage for local LLM inference (unified memory) |
| Windows 10/11 (native) | First-class | Tested in CI; some users may prefer WSL2 but it is not required |

WSL2 (Windows Subsystem for Linux) is supported as a side-effect of Linux support but is not recommended over native Windows install — there is no functionality gap.

### 16.3 Cross-Platform Discipline (Required for Contributors)

Code must work identically on all three platforms. Specific rules:

**Paths:**
- Always use `pathlib.Path`, never string concatenation
- Never hardcode `/home/user/...`, `~/.bbreport-assistant`, or similar; use `platformdirs`
- Never assume case-sensitive filesystems (macOS and Windows default to case-insensitive)
- Use `tempfile.gettempdir()` instead of `/tmp`

**File I/O:**
- Always specify `encoding="utf-8"` on every `open()` call
- Use `\n` for line endings in stored data; rely on OS conventions only at the output boundary
- Be mindful of file locking semantics (especially on Windows, where files in use cannot be deleted)

**Subprocess:**
- Do not shell out to Unix-only commands (`grep`, `awk`, `sed`, `find`). Use Python equivalents.
- If shelling out is unavoidable, gate it behind `sys.platform` checks with cross-platform fallbacks.

**Terminal output:**
- Use `rich` or `colorama` for colored output. Raw ANSI escape codes do not render correctly on legacy Windows terminals.
- Use Unicode characters cautiously; some Windows console configurations have encoding issues. Provide ASCII fallbacks for status indicators where possible (`[OK]` instead of `✓`, etc.) when the terminal doesn't support UTF-8.

**Testing:**
- CI runs on `ubuntu-latest`, `macos-latest`, and `windows-latest` for every PR
- A PR cannot merge if it fails on any platform
- New tests should not assume a specific OS unless explicitly testing OS-specific behavior

### 16.4 Installation

Universal path via PyPI works on all three platforms:

```bash
pip install bbreport-assistant
# or (recommended for CLI tools — isolates dependencies)
pipx install bbreport-assistant
```

Platform-specific install instructions live in the README and include the Ollama setup step (which differs per OS but is one command on each).

### 16.5 Pre-flight Check

`bbreport doctor` runs platform-aware diagnostics:
- Python version check
- OS detected and supported
- Ollama installed and reachable (checks platform-appropriate install paths)
- Default model pulled
- Config file present and valid at the OS-appropriate location
- Required directories writable
- Terminal supports the output capabilities the tool needs (color, Unicode)

### 16.6 Releases

- Semantic versioning (0.1.0 for first public release)
- GitHub Releases with changelog
- Signed releases once past v0.5
- PyPI publication (universal across OSes)
- Platform-specific package managers (Homebrew, Chocolatey, apt, etc.) considered only after v0.3 if there's demonstrated demand

### 16.7 CI/CD

GitHub Actions matrix from day one:

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, macos-latest, windows-latest]
    python-version: ["3.11", "3.12", "3.13"]
```

This is free for public repos and catches the vast majority of cross-platform issues before they reach users.

---

## 17. Security of the Tool Itself

The tool processes sensitive data. Its own security matters.

### 17.1 Threat Model

**In scope:**
- Local-only operation by default (no data exfiltration via tool)
- Tamper-evident audit logs (hash chain)
- No phone-home telemetry
- Cache isolation (no cross-user cache leakage on shared systems)

**Out of scope:**
- Endpoint compromise (if the user's machine is owned, we lose)
- LLM model security (we use third-party models; we trust they're not backdoored)
- Supply chain attacks against our dependencies (mitigated by lockfiles and minimal deps)

### 17.2 Specific Protections

- All file paths are validated; no traversal outside session directory
- Path validation accounts for OS-specific quirks: Windows drive letters (`C:\...`), UNC paths (`\\server\share`), case-insensitive filesystems on macOS/Windows, and reserved Windows filenames (CON, PRN, NUL, etc.)
- Evidence files are read-only after ingestion
- Cloud backend opt-in requires explicit `--allow-cloud` flag
- Sensitive-tagged evidence is never sent to cloud backends, even when configured

### 17.3 Responsible Disclosure for the Tool

A SECURITY.md file specifies how to report vulnerabilities in the tool itself. 90-day disclosure window, signed advisories.

---

## 18. Performance Targets (v0)

On the developer's machine (Core i5 11th gen, 8 GB RAM, Iris Xe, Qwen 2.5 3B q4):

- Evidence ingestion: < 1 second per file
- Single LLM call: 10–30 seconds
- Inference stage (5–8 fields, parallel): 30–90 seconds
- Adaptive elicitation (user-paced): variable, typically 1–3 minutes
- Full integrity verification (5 claims, 5 evidence items): 1–3 minutes
- Full compliance check: < 5 seconds (mostly deterministic)
- Full report render: < 1 second
- **End-to-end for typical report: 5–12 minutes** (most of it user thinking time)

These are acceptable for a tool used once per report. Real-time UX is not a goal.

---

## 19. What Future Versions Should Add

> See §0 for what is already built and the immediate next steps. The list below is the post-v0 roadmap.

In rough priority order (do not implement until v0 is shipped and stable):

- **v0.1 (current):** five vuln classes (XSS, SSRF, IDOR, CSRF, SQLi), full pipeline, mock + Ollama backends, CVSS v3.1, compliance + integrity layers, audit log — **implemented**. Remaining v0 hardening: live-model prompt tuning, public test corpus, golden/adversarial tests.
- **v0.2:** Bugcrowd platform support, two additional vuln classes (RCE, auth bypass), screenshot OCR
- **v0.3:** Multimodal verification (vision LLM checks screenshot content matches claim)
- **v0.4:** Plugin system formalized (entry points, third-party packages)
- **v0.5:** Web UI (Tauri-based desktop app)
- **v1.0:** Direct platform integration (HackerOne API submission)
- **v1.x:** Internal pentest report variant, vulnerability disclosure variant, compliance report variant

---

## 20. Anti-Goals (Explicit Decisions Not to Do Certain Things)

These are decisions to NOT do something, recorded so they're not relitigated:

- We will not auto-submit reports to platforms in v0. Researcher submits manually.
- We will not generate evidence the user didn't provide. Period.
- We will not include cloud LLM backends in default config.
- We will not store any user identification information.
- We will not include features that obfuscate the tool's involvement in producing a report. Watermarking/attribution is required.
- We will not support exploiting vulnerabilities, only documenting them.
- We will not provide a "submit anyway, ignore checks" mode without an explicit override flag and audit log entry.
- We will not offer separate "beginner" and "expert" modes. The same adaptive flow serves both.
- We will not designate any of Linux, macOS, or Windows as a second-class platform. If a feature works on two but not the third, the feature waits.

---

## 21. Glossary

- **Agent**: misnomer in our context; we use "assistant" or "supervisor" to avoid confusion with autonomous agents
- **Claim**: an assertion in the report that requires evidentiary support
- **CVE**: Common Vulnerabilities and Exposures — a specific identified vulnerability instance
- **CWE**: Common Weakness Enumeration — a class of weakness (e.g., CWE-79 = XSS)
- **Evidence**: a concrete artifact (request, response, image, code) supporting a claim
- **Field**: a single data point in a vuln class template (e.g., "rendering_context")
- **Inference**: the act of the LLM extracting a field value from evidence
- **Provenance**: the recorded link from a claim to its supporting evidence
- **Rule pack**: a YAML file encoding one bug bounty program's policies
- **Template**: a YAML file encoding one vulnerability class's structure
- **Compliance**: meeting the rule pack's requirements
- **Integrity**: claims being internally honest about what evidence shows
- **Triager**: the platform-side reviewer who decides report validity and severity
- **Hacktivity**: public disclosure feed on HackerOne (used for testing corpus)

---

## 22. References & Inspiration

- OWASP Top 10 for LLM Applications
- OWASP Agentic AI Threats and Mitigations
- NIST AI Risk Management Framework
- Simon Willison's writing on prompt injection and the "lethal trifecta"
- HackerOne Hacktivity (public disclosure corpus)
- CVSS v3.1 specification (FIRST.org)
- CWE (cwe.mitre.org)

---

## 23. End of Specification

This document evolves as the project does. Update version, changelog, and architecture sections when significant changes are made. Future contributors and AI assistants should treat this as authoritative for design questions.

**Related documents:**
- `PROJECT.md` — non-technical vision, rationale, roadmap
- `PLUGIN.md` — parked idea for a future Claude Code plugin / MCP server variant; not active work, but the architecture in this file is designed to support it without modification

**Version:** 0.3.0-spec / 0.1.0-impl (spec realized: 5 vuln classes, full pipeline, mock + Ollama backends, live-validated)
**Last Updated:** 2026-06-30 — v0 live-validated end-to-end on OWASP Juice Shop; see §0 for status and next steps
**Status:** living document

**Changelog:**
- 2026-06-30: Live end-to-end validation against OWASP Juice Shop (real DOM-XSS) on the local Ollama model; added `owasp:juice-shop` program pack, local-LLM setup guide, and Juice Shop walkthrough; made the mock backend host-aware for endpoint inference; pre-GitHub docs pass (README landing page, workflow diagram). `evidence/`/`examples/` git-ignored.
- 2026-06-29: v0 implementation complete. Built full package, all six stages, five vuln-class templates, deterministic layers (CVSS v3.1, compliance, provenance DAG, audit hash chain), mock + Ollama backends, CLI, and 33 tests. Generalized the claim engine and renderers to be class-agnostic (see §0 conventions). Next: live-model tuning + test corpus.
- (prior) 0.3.0-spec: adaptive elicitation + inference engine + cross-platform support added to the spec.
