# Walkthrough: DOM XSS in OWASP Juice Shop, end-to-end with ProofForge AI

This walks a real finding from evidence capture to a finished report, using:
- **Target:** a local Docker Juice Shop, `http://localhost:3000`
- **Vulnerability:** DOM-based XSS in the product search
- **Capture tool:** Burp Suite
- **LLM:** local Ollama (`qwen2.5:3b-instruct-q4_K_M`) — see
  [setup_local_llm.md](setup_local_llm.md) first.

> **Authorization.** OWASP Juice Shop is intentionally vulnerable and published for
> training, so testing it is authorized. Running it locally means you own the target —
> test freely. (The `owasp:juice-shop` program pack also covers `demo.owasp-juice.shop`
> if you ever use the shared public demo, which should be hit gently and by hand only.)

## 0. Start Juice Shop in Docker

```powershell
docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop
```
Wait a few seconds, then open <http://localhost:3000>. To stop/remove later:
`docker rm -f juice-shop`. Point Burp's proxy at this origin to capture traffic.

---

## 1. Understand the bug

Juice Shop's search reflects the query into the page DOM without sanitization. The
payload executes **client-side from the URL fragment** — the server never renders it.
That detail matters for evidence (below).

A classic payload (older Juice Shop builds; adjust if patched):
```
<iframe src="javascript:alert(`xss`)">
```
Entered in the search box, the URL becomes:
```
http://localhost:3000/#/search?q=<iframe src="javascript:alert(`xss`)">
```
and an `alert` box pops — that's your proof of execution.

## 2. Capture evidence in Burp

Because the bug is DOM-based, **the screenshot of the alert is your primary proof.**
The HTTP request/response are supporting context (the search API returns product JSON
and will *not* contain your executing payload — that's normal for DOM XSS).

Collect four files into a folder, e.g. `~/juiceshop-xss/`:

| File | Type | How to get it |
|---|---|---|
| `request.txt` | `http_request` | In Burp **Proxy ▸ HTTP history**, find `GET /rest/products/search?q=<payload>`. Right-click ▸ **Copy** the raw request → paste into the file. |
| `response.txt` | `http_response` | From the same item, copy the raw response (the JSON product list). |
| `screenshot.png` | `screenshot` | Screenshot of the `alert()` firing in the browser. **This is the key proof.** |
| `repro.md` | `repro_steps` | Write the exact URL + numbered steps to reproduce. |

A good `repro.md`:
```
1. Open http://localhost:3000/#/search?q=<iframe src="javascript:alert(`xss`)">
2. Observe a JavaScript alert box reading "xss" — arbitrary JS executed in the
   origin of the application.
3. The payload originates from the `q` value in the URL fragment, rendered into
   the search-results DOM without sanitization (DOM-based XSS).
```

### Sample file formats (copy these, then replace with your real capture)

`request.txt` — the raw search request (note the URL-encoded payload in `q`):
```
GET /rest/products/search?q=%3Ciframe%20src%3D%22javascript%3Aalert%28%60xss%60%29%22%3E HTTP/1.1
Host: localhost:3000
User-Agent: Mozilla/5.0
Accept: application/json, text/plain, */*
Referer: http://localhost:3000/
```

`response.txt` — the JSON response (deliberately does **not** contain the payload; DOM XSS executes client-side):
```
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
X-Content-Type-Options: nosniff

{"status":"success","data":[]}
```

`repro.md` — the URL + steps (include the **decoded** payload for readability), and note that the
screenshot of the alert is the primary proof.

> These are illustrative templates — capture your own request/response/screenshot from Burp before
> producing a report you intend to submit.

## 3. Run the ProofForge pipeline

```powershell
# 1. Start a session against the Juice Shop program pack
bbreport init --program owasp:juice-shop

# 2. Register the evidence (run from your capture folder)
bbreport evidence add -f request.txt    -t http_request
bbreport evidence add -f response.txt   -t http_response
bbreport evidence add -f screenshot.png -t screenshot
bbreport evidence add -f repro.md       -t repro_steps
bbreport evidence list

# 3. Build the report — the live model infers fields from your evidence
bbreport report new --vuln-class xss --subtype dom_based
```

During `report new` the inference engine pre-fills what it can (affected endpoint,
injection vector, payload) and presents them for confirmation. You'll typically:
- **Confirm** the endpoint and payload it extracted from your request.
- **Set `rendering_context`** yourself — for this DOM XSS it's `url_context` (payload
  comes from the URL) reflected into the body; pick what your screenshot/DOM shows.
- **Write the impact** (it offers a draft): e.g. *"Arbitrary JavaScript executes in the
  application's origin when a victim opens a crafted search URL, enabling session/UI
  attacks against the logged-in user."* Claim only what your screenshot demonstrates.

```powershell
# 4. Integrity (Gap 1) and compliance (Gap 3)
bbreport verify
bbreport check

# 5. Render the final report
bbreport render -o report.md
```

You get `report.md`, `integrity_summary.json`, and a hash-chained `audit.jsonl`
(verify it any time with `bbreport audit verify audit.jsonl`).

## 4. Reading the integrity output for DOM XSS

`bbreport verify` runs the LLM verifier against each claim/evidence pair. For DOM XSS,
the **`http_response` won't contain the executing payload**, so the verifier may report
the response only *partially* supports the "executes in the browser" claim. That's
correct, not a bug — the proof lives in the **screenshot + repro_steps**, not the JSON.

Three ways to resolve a flagged claim (spec §9.3):
- **Lean on the right evidence** — make sure the impact claim is backed by the
  screenshot and repro, not just the API response.
- **Soften the claim** — re-run `report new` and phrase the impact to match exactly what
  the screenshot shows (e.g. "alert() executed" rather than "session token stolen",
  unless you actually demonstrated exfiltration).
- **Override** — proceed with an explicit acknowledgement; this is recorded in the audit
  log. Orphan/hash checks cannot be overridden.

## 5. Tips

- First model call is slow (loads the model); later calls are cached. Use `--no-cache`
  only when you change prompts.
- Prefer a **local** Juice Shop for repeatable captures; the demo site is shared.
- To iterate fast on the *format* without the model, set `llm.backend: mock` and dry-run
  with the sample files above (the mock returns canned values, so the pipeline completes instantly).
