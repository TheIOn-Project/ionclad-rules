# shared-rules CHANGELOG

All notable changes to rule packs. Drift audit reference.

---

## 2026-05-14 — Scanner expansion sprint (P1–P6) + post-audit fixes

Cross-pack release notes. 61 net-new rules across one new pack (LLM
security) and three extended packs (Vibe, Framework, Deploy already
extended 2026-05-14 with DP33–DP39). Plus 10 Rust-only rules in
`thirdparty_scanner.rs` (TP14–TP18) and `owasp_web_scanner.rs`
(OW80–OW84) that are not in any JSON pack yet.

- **llm-security.json** — NEW, v1.0.0. 23 rules (LLM01–LLM23) covering
  prompt injection, system prompt leakage, PII to LLM vendors, unsafe
  LLM-output rendering, unsandboxed function-calling tools, cost/DoS,
  deprecated models, client-side keys.
- **framework.json** — v1.0.0 → v1.2.1. +18 rules: FW70–FW79 (webhook
  signature verification: Stripe / GitHub / Clerk / Polar / Linear /
  Slack / Shopify / generic / HMAC `==` / `JSON.stringify` antipattern)
  and FW80–FW87 (file upload validation: multer / formidable / busboy
  + originalname path traversal + dangerous extension allowlist).
  Post-audit 1.2.1 fix: FW80/FW81 switched from whole-file
  `exclude_contains` to `context_filter: exclude_nearby_keyword`
  (per-call windowed check; the old behavior missed a bad multer call
  when another multer call in the same file had fileFilter/limits).
- **vibe.json** — v1.0.0 → v1.1.0. +10 rules (V60–V69) covering
  Math.random for tokens, MD5/SHA1 for password hashing, hardcoded IV
  in createCipheriv, AES-ECB mode, deprecated createCipher,
  RSA-PKCS1 v1.5 padding, static salt in PBKDF2/scrypt, HMAC
  comparison with `==` (V68 — overlay version of FW78, fires when
  framework not detected), Python hashlib MD5/SHA1 for passwords.
  Also V35 regex expanded to catch `bcrypt.hash(password, 8)` form
  in addition to `bcrypt(8)` / `genSalt(8)`.

Rule pack count after release: 6 packs, **167 rules** (was 109 before
2026-05-14 session).

---

## Schema

### 1.1.0 — 2026-04-19
- **Added** `exclude_nearby_keyword` variant to `ContextFilter`. Inverse of `nearby_keyword`: rejects matches where any listed keyword appears in the window. Supports `direction: "before" | "after" | "around"` (default `around`).
- **Added** `match_once: boolean` field to `RegexRule`. When `true`, emits at most one finding per file even if the regex matches multiple times. Mirrors desktop's common `break` pattern.
- **Changed** context filters from single `keyword: string` to `keywords: string[]` (OR semantics — at least one present means the filter matched). Unlocks V50-style "exclude if `await` OR `return` nearby" rules.
- Runner, validator, and SCHEMA.md all updated to match.

### 1.0.0 — 2026-04-18
- Initial schema: `regex` · `entropy` · `ast` rule kinds
- AST rules reserved; web runner v1 skips with warning (activated Sprint 6)
- Validator: `shared-rules/validate.mjs`

---

## secret.json

### 1.0.1 — 2026-04-19
- **Changed** S25 (Heroku API Key) from `keyword: "heroku"` to `keywords: ["heroku"]` for schema v1.1.0 compatibility. No semantic change.

### 1.0.0 — 2026-04-18
- Initial extraction from `src-tauri/src/engine/scanners/secret_scanner.rs`
- 29 regex rules + 1 entropy rule (S99)
- Special filters preserved: S25 Heroku context, S30/S31/S32 placeholder suppression, S99 scope + shape exclusions
- Every regex validated in JS RegExp engine
- Rust regex compatibility pending `cargo check` (v2.1 Core SDK extraction)

---

## vibe.json

### 1.1.0 — 2026-05-14 (P4: cryptography misuse)
- **Added** 10 rules V60–V69 covering: Math.random for token/ID
  generation (V60), MD5 for password hashing (V61), SHA-1 for password
  hashing (V62), hardcoded string IV in createCipheriv (V63), AES-ECB
  mode (V64), crypto.createCipher deprecated API (V65), RSA-PKCS1 v1.5
  padding (V66), static salt in PBKDF2/scrypt (V67), HMAC compared
  with `==` (V68 — overlay version of FW78, fires when framework not
  detected), Python hashlib MD5/SHA1 for passwords (V69).
- **Changed** V35 regex from `(?:bcrypt|genSalt|gensalt)\s*\(\s*([1-9])\s*\)`
  to `(?:bcrypt\.(?:hash|hashSync|genSalt|genSaltSync)|bcrypt|genSalt|gensalt)\s*\((?:[^,)]*,\s*)?([1-9])\s*\)`
  — now catches `bcrypt.hash(password, 8)` form in addition to the
  bare `bcrypt(8)` / `genSalt(8)` forms. Drift risk: re-run V35
  fixtures.

### 1.0.0 — 2026-04-19
- Initial extraction from `src-tauri/src/engine/scanners/vibe_pack.rs`
- **17 rules** (14 parent rules, V56 split into V56a/b/c/d for the four debug-mode variants)
- Rules: V11, V35, V36, V39, V40, V44, V48, V49, V50, V51, V52, V55, V56a/b/c/d, V57
- V50 + V55 use the new `exclude_nearby_keyword` filter (direction "before", 120-char window) for "regex match AND no await/return in preceding line"
- **Known gap:** V02 (`.env` not in `.gitignore`) intentionally skipped — requires per-line structural analysis that doesn't fit the regex schema. Slated for a future `gitignore` rule kind.
- Classified as `overlay: true` (fires on every scan)

---

## framework.json

### 1.2.1 — 2026-05-14 (post-audit fix)
- **Changed** FW80 and FW81 from `exclude_contains: ["fileFilter"]` /
  `exclude_contains: ["limits"]` (whole-file check) to
  `context_filter: exclude_nearby_keyword` with `direction: "after"`
  and `window_chars: 400`. Reason: a file with one good
  `multer({fileFilter: ...})` and one bad `multer({})` was suppressing
  the finding entirely. The per-call windowed check fires correctly
  on the bad call without being fooled by the good one.

### 1.2.0 — 2026-05-14 (P3: file upload validation)
- **Added** 8 rules FW80–FW87 covering: multer without fileFilter
  (FW80), multer without limits (FW81), multer dest in web-served
  directory (FW82, Critical — stored XSS vector), formidable without
  maxFileSize (FW83), originalname used in path construction (FW84,
  Critical — path traversal), file extension allowlist contains
  dangerous types like .svg/.html/.js/.mjs (FW85, Critical),
  multer.diskStorage filename returns originalname unsanitized (FW86,
  Critical), Busboy without limits (FW87).

### 1.1.0 — 2026-05-14 (P2: webhook signature verification)
- **Added** 10 rules FW70–FW79 covering: Stripe webhook without
  constructEvent (FW70), GitHub webhook without X-Hub-Signature-256
  (FW71), Clerk without svix verify (FW72), Polar without
  validateEvent (FW73), Linear without linear-signature (FW74),
  Slack Events without X-Slack-Signature (FW75), Shopify without
  X-Shopify-Hmac (FW76), generic /webhook/ route without ANY
  signature primitives (FW77), HMAC compared with `==` (FW78),
  Stripe constructEvent with `JSON.stringify(req.body)` antipattern
  (FW79).

### 1.0.0 — 2026-04-19
- Initial extraction from `src-tauri/src/engine/scanners/framework_scanner.rs`
- **18 rules** covering Express (FW01-04), Next.js (FW10-12), Django (FW20-23), Flask (FW30-31), Rails (FW40-41), Laravel (FW50), React/Vue (FW60-61)
- FW10 tightened from desktop's "missing `headers` OR missing `X-Frame-Options`" to the stricter "missing `X-Frame-Options`" using the virtual-anchor trick (regex `^` + `exclude_contains`)
- FW23 covers only the explicit `SECURE_SSL_REDIRECT = False` case, not the absence-of-setting case (deferred)
- Classified as `overlay: false` (framework-specific, fires on matching files)

---

## deploy.json

### 1.0.0 — 2026-04-19
- Initial extraction from `src-tauri/src/engine/scanners/deploy_scanner.rs`
- **31 rules** covering NODE_ENV, source maps, health checks, graceful shutdown, error tracking, stack trace leaks, TLS verification, DB SSL, process manager, logging, Django/Flask prod, CORS, Kubernetes probes and resource limits
- Rules: DP01-24, DP26-32
- **Known gap:** DP25 (production dependencies in `devDependencies`) skipped — desktop does section-based JSON substring matching which is a structural rather than regex-based check. Single Low-severity finding; slated for desktop parity in a future sprint.
- Uses `match_once: true` extensively to mirror desktop's "break after first match" pattern
- Classified as `overlay: true` (every project ships somewhere)

---

## llm-security.json

### 1.0.0 — 2026-05-14 (P1: AI/LLM application security pack — NEW)
- Initial release. **23 rules** (LLM01–LLM23) extracted from
  `src-tauri/src/engine/scanners/llm_scanner.rs`.
- Covers prompt injection (LLM01–04 — JS/Python user input in
  template-literal prompts, system-role messages, f-strings), system
  prompt leakage in frontend code (LLM05), raw PII in LLM call sites
  (LLM06–08 — emails, SSNs, credit cards), LLM output rendered as
  HTML via innerHTML / dangerouslySetInnerHTML / unsanitized markdown
  (LLM09–11), function-calling tools with shell / eval / fs.writeFile
  access (LLM12–14), missing max_tokens for cost control (LLM15),
  deprecated model snapshots (LLM16), model name from user input
  (LLM17, billing-DoS), streaming without abort signal (LLM18),
  LangChain ShellTool imported (LLM19), LLM SDK in client-side code
  with apiKey (LLM20), `dangerouslyAllowBrowser: true` (LLM21),
  unbounded agent loops without max_iterations (LLM22), embeddings.create
  with user input lacking length cap (LLM23).
- Classified as `overlay: true` — runs on every scan.

---

## privacy.json

### 1.0.0 — 2026-04-19
- Initial extraction from `src-tauri/src/engine/scanners/privacy_scanner.rs`
- **13 rules** covering GDPR, CCPA, App Store, Google Play Data Safety compliance and PII detection
- Rules: P01-P03 (PII in logs), P10 (analytics without consent), P11 (tracking pixels), P12 (PII in URLs), P13 (cookies without banner), P14 (no privacy policy link), P15 (PII in error tracker), P20 (no retention), P21 (CCPA do-not-sell), P25 (Apple ATT), P26 (Android Data Safety)
- P10 and P11 use regex alternation over multiple providers — emits one finding per file instead of desktop's one-finding-per-provider-match; net: same semantic, slightly generic finding name
- P15 combines error-tracker prefix + PII keyword into a single alternation regex instead of desktop's per-tracker loop
- Classified as `overlay: true` (fires on every scan regardless of project type)

---

## Summary at end of Sprint 5

| Pack      | Version | Rules | Overlay | Category  |
|-----------|---------|-------|---------|-----------|
| secret    | 1.0.1   |    30 | yes     | secrets   |
| vibe      | 1.0.0   |    17 | yes     | vibe      |
| framework | 1.0.0   |    18 | no      | framework |
| deploy    | 1.0.0   |    31 | yes     | deploy    |
| privacy   | 1.0.0   |    13 | yes     | privacy   |
| **total** |         | **109** |       |           |

---

## Summary at end of P1–P6 sprint (2026-05-14, web-1.0.0)

| Pack          | Version | Rules | Overlay | Category      |
|---------------|---------|-------|---------|---------------|
| secret        | 1.0.3   |    30 | yes     | secrets       |
| vibe          | 1.1.0   |    27 | yes     | vibe          |
| framework     | 1.2.1   |    36 | no      | framework     |
| deploy        | 1.1.0   |    38 | yes     | deploy        |
| privacy       | 1.0.0   |    13 | yes     | privacy       |
| llm-security  | 1.0.0   |    23 | yes     | llm-security  |
| **total**     |         | **167** |       |               |
