# shared-rules CHANGELOG

All notable changes to rule packs. Drift audit reference.

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

### 1.0.3 — 2026-04-28
- **Changed** S08 (Google API Key) — added `scope.exclude_path_suffixes` for `google-services.json` (Firebase Android config) and `GoogleService-Info.plist` (Firebase iOS config). Both files are public-by-design per Firebase documentation; the `AIza` key inside is restricted server-side by SHA-1 + package_name (Android) or bundle ID (iOS), not by secrecy. Flagging them as Critical was a true false positive that flipped clean Firebase apps to NOT READY (FP baseline project #3, an Android app, hit this).
- Note text expanded slightly to remind users to verify the Cloud Console restriction is configured (the user-side audit responsibility the scanner can't infer from the file alone).

### 1.0.2 — 2026-04-28
- **Changed** S99 (High-Entropy String) — comprehensive FP tuning after first real-project baseline (IOn-Herd-App scan returned **1060** S99 hits, all on `package-lock.json` integrity hashes).
  - Added 4 hash formats to `shape_exclusions`: sha256 hex (`[a-f0-9]{64}`), sha512 hex (`[a-f0-9]{128}`), npm/yarn integrity prefix (`sha[0-9]+-...`), UUIDs (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`). Pre-existing git SHA-1 (`[a-f0-9]{40}`) retained.
  - Extended `scope.exclude_path_suffixes` from 2 → 14 entries. Added 12 lockfile filenames covering Node (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lockb`), Rust (`Cargo.lock`), Python (`poetry.lock`, `Pipfile.lock`), PHP (`composer.lock`), Ruby (`Gemfile.lock`), Go (`Gopkg.lock`), Elixir (`mix.lock`), Nix (`flake.lock`).
  - `min_entropy_bits` kept at 5.0 — real secrets cluster at 4.5–5.5 (AWS access keys, GitHub PATs, Stripe keys), so raising the floor would miss them. The fix is shape/path precision, not threshold elevation.
- Pack version 1.0.0 → 1.0.2 (1.0.1 was the keyword schema migration documented below; never landed in the version field).

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

### 1.0.1 — 2026-04-28
- **Changed** V52 (CORS Set to Reflect Origin or Wildcard) — refined `note` and `remediation` text to differentiate the two cases the regex matches. Origin reflection is the high-risk pattern (especially with credentials); wildcard `*` is often intentional on public read-only endpoints (badges, public stats, status APIs). Severity stays High because reflection is still high-risk; the new text labels the wildcard-on-public case as a legitimate suppression. FP baseline project #2 (IOn Probe) flagged a public badge handler — now self-documenting as a known suppression-worthy true positive.
- **Open question for v1.1+**: split V52 into V52a (reflection, High) and V52b (wildcard, Medium) so the severity reflects the actual risk profile. Deferred to avoid rule-ID churn during launch sprint.

### 1.0.0 — 2026-04-19
- Initial extraction from `src-tauri/src/engine/scanners/vibe_pack.rs`
- **17 rules** (14 parent rules, V56 split into V56a/b/c/d for the four debug-mode variants)
- Rules: V11, V35, V36, V39, V40, V44, V48, V49, V50, V51, V52, V55, V56a/b/c/d, V57
- V50 + V55 use the new `exclude_nearby_keyword` filter (direction "before", 120-char window) for "regex match AND no await/return in preceding line"
- **Known gap:** V02 (`.env` not in `.gitignore`) intentionally skipped — requires per-line structural analysis that doesn't fit the regex schema. Slated for a future `gitignore` rule kind.
- Classified as `overlay: true` (fires on every scan)

---

## framework.json

### 1.0.0 — 2026-04-19
- Initial extraction from `src-tauri/src/engine/scanners/framework_scanner.rs`
- **18 rules** covering Express (FW01-04), Next.js (FW10-12), Django (FW20-23), Flask (FW30-31), Rails (FW40-41), Laravel (FW50), React/Vue (FW60-61)
- FW10 tightened from desktop's "missing `headers` OR missing `X-Frame-Options`" to the stricter "missing `X-Frame-Options`" using the virtual-anchor trick (regex `^` + `exclude_contains`)
- FW23 covers only the explicit `SECURE_SSL_REDIRECT = False` case, not the absence-of-setting case (deferred)
- Classified as `overlay: false` (framework-specific, fires on matching files)

---

## deploy.json

### 1.0.1 — 2026-04-28
- **Changed** DP14 (Node Started Without Process Manager) — added `"\"bin\":"` and `"\"preferGlobal\""` to `exclude_contains`. Both are package.json-level CLI markers: the `"bin":` key registers an npm-installed CLI executable, and `"preferGlobal": true` is the explicit "this is a CLI, not a server" signal. Express-style server projects with a `bin/www` startup script do NOT have these JSON keys (just a path string), so they remain flagged. FP baseline project #2 (IOn Probe) hit this on `ion-probe-cli/package.json` where PM2 advice is nonsense for a one-shot CLI invocation.

### 1.0.0 — 2026-04-19
- Initial extraction from `src-tauri/src/engine/scanners/deploy_scanner.rs`
- **31 rules** covering NODE_ENV, source maps, health checks, graceful shutdown, error tracking, stack trace leaks, TLS verification, DB SSL, process manager, logging, Django/Flask prod, CORS, Kubernetes probes and resource limits
- Rules: DP01-24, DP26-32
- **Known gap:** DP25 (production dependencies in `devDependencies`) skipped — desktop does section-based JSON substring matching which is a structural rather than regex-based check. Single Low-severity finding; slated for desktop parity in a future sprint.
- Uses `match_once: true` extensively to mirror desktop's "break after first match" pattern
- Classified as `overlay: true` (every project ships somewhere)

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
| secret    | 1.0.3   |    30 | yes     | secrets   |
| vibe      | 1.0.1   |    17 | yes     | vibe      |
| framework | 1.0.0   |    18 | no      | framework |
| deploy    | 1.0.1   |    31 | yes     | deploy    |
| privacy   | 1.0.0   |    13 | yes     | privacy   |
| **total** |         | **109** |       |           |

## FP baseline projects scanned (live web scanner)

| # | Project              | Type           | Pre-fix verdict | Post-fix verdict | Rules tightened |
|---|----------------------|----------------|-----------------|------------------|-----------------|
| 1 | IOn-Herd-App         | React Native   | F · 0/100 · ship_it (1060 hits)  | A · 90/100 · ship_it (4 hits) | S99 (secret 1.0.0→1.0.2) |
| 2 | IOn-Probe-Sprint-23  | Worker + UI + CLI | B · 88/100 · ship_it (3 hits) | (pending re-scan)             | DP14, V52 (deploy 1.0.0→1.0.1, vibe 1.0.0→1.0.1) |
| 3 | ionreclaim-v1.6.1    | Android (Firebase) | B · 80/100 · not_ready (1 critical FP) | (pending re-scan)             | S08 (secret 1.0.2→1.0.3) |
