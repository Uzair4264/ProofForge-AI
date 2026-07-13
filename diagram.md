# ProofForge AI — Workflow & Architecture Diagrams

GitHub renders the Mermaid blocks below as images. To export a picture: open this file on GitHub
(or in VS Code with a Mermaid preview extension) and screenshot, or paste the Mermaid source into
<https://mermaid.live> and download an SVG/PNG.

---

## 1. The pipeline (what happens to your evidence)

```mermaid
flowchart TD
    A["📥 INPUT<br/>Raw evidence: HTTP request/response,<br/>screenshots, repro steps<br/>+ target program"]:::io

    A --> S1["STAGE 1 — Ingestion & Classification<br/><i>parse evidence, hash + provenance,<br/>LLM classifies vuln class</i>"]
    S1 --> S2["STAGE 2 — Inference Engine<br/><i>LLM pre-fills template fields<br/>from the evidence (with confidence)</i>"]
    S2 --> S3["STAGE 3 — Adaptive Elicitation<br/><i>confirm inferred values;<br/>ask only what's missing</i>"]
    S3 --> S4["STAGE 4 — Integrity / Gap 1<br/><i>claim→evidence DAG:<br/>orphan, over-reach, consistency</i>"]
    S4 --> S5["STAGE 5 — Compliance / Gap 3<br/><i>scope, required fields,<br/>forbidden content, CVSS v3.1</i>"]
    S5 --> S6["STAGE 6 — Rendering<br/><i>program-formatted, dual-audience<br/>report with evidence refs</i>"]
    S6 --> O["📤 OUTPUT<br/>report.md · integrity_summary.json<br/>· hash-chained audit.jsonl"]:::io

    classDef io fill:#0b3d2e,stroke:#19c37d,color:#e8fff5;
    classDef llm stroke-dasharray: 5 5;
    class S1,S2,S4,S5 llm;

    L["🔒 Local by default — evidence never leaves your machine.<br/>Dashed stages call the LLM (advisory only; you confirm).<br/>Severity, scope, hashing are deterministic code."]:::note
    classDef note fill:#1f2933,stroke:#6b7280,color:#e5e7eb;
```

**Legend:** dashed boxes (Stages 1, 2, 4, 5) invoke the LLM for a narrow sub-task; everything else is
deterministic Python. The LLM is always *advisory* — the researcher confirms every value.

---

## 2. Layered architecture (how the code is organized)

```mermaid
flowchart TD
    CLI["CLI (Typer + Rich)<br/>init · evidence · report · verify · check · render · audit · doctor"]
    CLI --> ORCH["core/orchestrator.py<br/><i>drives the 6 stages; no domain logic</i>"]

    ORCH --> INF["inference/engine.py<br/>field inference"]
    ORCH --> VCE["vuln_classes/engine.py<br/>+ templates/*.yaml<br/>(XSS·SSRF·IDOR·CSRF·SQLi)"]
    ORCH --> EVID["evidence/<br/>ingester · provenance DAG · verifier"]
    ORCH --> ENF["program_packs/enforcer.py<br/>+ packs/*.yaml"]
    ORCH --> SEV["severity_frameworks/<br/>cvss_v31.py"]
    ORCH --> OUT["output_formats/<br/>markdown · hackerone_md"]
    ORCH --> AUD["audit/<br/>hash-chained log"]

    INF --> BE
    VCE --> BE
    EVID --> BE
    ENF --> BE
    BE["llm_backends/base.py<br/><b>swappable LLM interface</b>"]
    BE --> OLL["Ollama<br/>qwen2.5:3b (local)"]
    BE --> MOCK["Mock<br/>(offline / tests)"]
    BE --> CLOUD["OpenAI-compatible<br/>(opt-in, --allow-cloud)"]

    classDef data fill:#10243e,stroke:#3b82f6,color:#dbeafe;
    class VCE,ENF data;
```

**Key design choice:** the LLM lives behind one small interface (`llm_backends/base.py`). Swapping
Ollama for a bigger model, the offline mock, or a future Claude/MCP backend is a new file — not a
refactor. Vulnerability classes and program rules are **data (YAML), not code**.

---

## 3. ASCII fallback (the pipeline)

```
            ┌─────────────────────────────────────────────┐
   INPUT    │ evidence (HTTP, screenshots, repro) + program│
            └───────────────────────┬─────────────────────┘
                                    ▼
   STAGE 1  Ingestion & Classification   parse · hash · classify (LLM)
                                    ▼
   STAGE 2  Inference Engine            LLM pre-fills fields + confidence
                                    ▼
   STAGE 3  Adaptive Elicitation        confirm inferred · ask the rest
                                    ▼
   STAGE 4  Integrity  (Gap 1)          claim→evidence DAG: orphan / over-reach (LLM)
                                    ▼
   STAGE 5  Compliance (Gap 3)          scope · required fields · CVSS v3.1
                                    ▼
   STAGE 6  Rendering                   program-formatted dual-audience report
                                    ▼
            ┌─────────────────────────────────────────────┐
   OUTPUT   │ report.md · integrity_summary.json · audit.jsonl (hash-chained)
            └─────────────────────────────────────────────┘

   Local by default · LLM advisory only (you confirm) · deterministic severity/scope/hashing
```
