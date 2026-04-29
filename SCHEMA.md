# IOnclad Shared Rule Schema — v1

**Status:** Canonical source of truth for IOnclad scanner rules.
**Consumers:** `ionclad-web/` (live as of v2.0.0-beta) · `src-tauri/` (as of v2.1 Core SDK extraction).

This document specifies the JSON format rule packs use. The goal is
one rule definition that produces identical findings on desktop Rust
and web TypeScript runners. `schema.ts` is the authoritative
TypeScript definition; this document explains the *why* behind each
field.

---

## Design principles

1. **Declarative over procedural.** A rule describes *what* to detect,
   not *how*. The runner implements the how. This keeps rules
   portable across Rust and TS without embedding runtime logic.

2. **Progressive expressiveness.** 90% of rules are plain regex
   matches. The schema supports that simply. Rules with more nuance
   (context filters, value suppressions, multi-condition) opt into
   additional fields as needed.

3. **Forward-compat.** Unknown fields on a rule do not fail
   validation; runners skip what they don't understand. New rule
   kinds can be introduced without breaking older runners (they
   ignore the new kind).

4. **Finding shape parity.** The output of a rule match on either
   runner must produce an equivalent `Finding` object. Field names
   and values match the desktop Rust `Finding` struct exactly.

---

## Top-level: RulePack

Every file under `shared-rules/*.json` (except `pack-meta.json`) is a
`RulePack` — the unit of distribution for one scanner.

```jsonc
{
  "$schema": "../shared-rules/SCHEMA.md#v1",
  "scanner_id": "secrets",           // matches src-tauri scanner::SECRETS
  "scanner_name": "Secret Scanner",
  "scanner_description": "Detects hardcoded API keys, tokens, and credentials.",
  "category": "secrets",             // default cat:: for rules in this pack
  "version": "1.0.0",                // bump on any rule change
  "overlay": true,                   // fires regardless of app type
  "rules": [ /* Rule[] */ ]
}
```

| Field | Type | Description |
|---|---|---|
| `$schema` | `string` | Pinned schema version reference. Runners validate this matches their supported version. |
| `scanner_id` | `string` | Unique scanner identity. Must match the `scanner::*` constants in `src-tauri/src/engine/categories.rs` and the `SCANNERS[*].id` in `src/data/scanners.ts`. |
| `scanner_name` | `string` | Human-readable display name. |
| `scanner_description` | `string` | One-line summary shown in scanner cards. |
| `category` | `string` | Default finding category (`cat::*`). Individual rules may override. |
| `version` | `string` | Semver. Bumped on any rule addition, removal, or semantic change. Used for drift detection. |
| `overlay` | `boolean` | If `true`, this scanner runs on every scan. If `false`, only runs when its target framework/language is detected. |
| `rules` | `Rule[]` | The rule definitions themselves. |

---

## Rule kinds

A rule is a tagged union. The `kind` field discriminates. v1 defines
three kinds: `regex`, `entropy`, and `ast`.

### Common fields (on every rule kind)

```jsonc
{
  "kind": "regex",              // discriminator
  "id": "S01",                  // stable identifier — never renumber
  "name": "AWS Access Key ID",  // human-readable
  "severity": "Critical",       // Critical | High | Medium | Low
  "note": "AWS Access Key grants API access to AWS services.",
  "remediation": "Deactivate in IAM, rotate, use env vars.",
  "category": "secrets",        // optional — defaults to pack.category
  "owasp_ref": "A07:2021",      // optional — OWASP Top 10 reference
  "mobile_ref": null            // optional — OWASP Mobile reference
}
```

| Field | Required | Description |
|---|---|---|
| `kind` | ✓ | `"regex"` \| `"entropy"` \| `"ast"` |
| `id` | ✓ | Stable identifier. Desktop and web must emit findings with the same `id` for the same defect. |
| `name` | ✓ | Title shown in findings table. |
| `severity` | ✓ | One of four levels. Drives score and verdict. |
| `note` | ✓ | 1-2 sentence explanation of the risk. |
| `remediation` | ✓ | Actionable fix guidance. |
| `category` | – | Overrides `pack.category` if present. |
| `owasp_ref` | – | e.g., `"A07:2021"`. |
| `mobile_ref` | – | OWASP Mobile reference for iOS/Android rules. |

### Rule kind: `regex`

A regex rule matches literal or captured text in file content. This is
80% of all rules.

```jsonc
{
  "kind": "regex",
  "id": "S25",
  "name": "Heroku API Key",
  "severity": "High",
  "note": "Possible Heroku API key (UUID format near 'heroku' context).",
  "remediation": "Regenerate in Heroku Account Settings.",
  "regex": "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
  "regex_flags": "",                    // optional: "i" | "m" | "s" | combinations
  "scope": {
    "extensions": ["js", "ts", "py"],
    "path_suffixes": [".env"],
    "exclude_extensions": ["map", "min.js"],
    "exclude_path_suffixes": ["node_modules/"]
  },
  "require_contains": ["heroku"],       // content must also contain all of these (case-insensitive)
  "exclude_contains": [],               // content must NOT contain any of these (kills the rule for this file)
  "context_filter": {
    "type": "nearby_keyword",
    "keyword": "heroku",
    "window_chars": 50
  },
  "value_suppressions": [
    { "type": "placeholder_fragments", "fragments": ["example", "test", "mock"] }
  ],
  "capture_group": 1                    // optional — which capture group holds the reportable value
}
```

**Regex dialect:** rules MUST use regex syntax that works in both Rust's
`regex` crate and JavaScript's `RegExp`. Differences to watch:

- `(?i)` inline flag works in Rust; use `regex_flags: "i"` for web equivalence
- Lookahead/lookbehind: Rust's `regex` crate does NOT support these. Avoid.
- `\d`, `\w`, `\s`: both engines support these identically
- `[^...]` character classes: identical
- Non-capturing groups `(?:...)`: identical
- Backreferences `\1`: Rust's `regex` does not support these. Avoid.

If a rule needs functionality one engine doesn't support, split it
into two passes using `require_contains` / `exclude_contains` instead.

**Scope:** filters the files this rule examines.

- `extensions`: match any extension in the list (no leading dot)
- `path_suffixes`: match if file path ends with any suffix
- `path_patterns`: glob patterns (e.g., `**/docker-compose*.yml`)
- `exclude_*`: the inverse — if any match, skip the file

When omitted, the rule runs against all text files.

**require_contains / exclude_contains:** whole-file content checks
evaluated BEFORE the main regex. If `require_contains` is set, every
string in the list must appear in the file (case-insensitive) or the
rule is skipped for that file. Useful for the V48 pattern:

```jsonc
{
  "require_contains": ["jwt.decode("],
  "exclude_contains": ["jwt.verify("]
}
```

**context_filter:** evaluated AFTER a regex match, on the surrounding
content. If the filter rejects, the match is discarded.

- `nearby_keyword`: one keyword must appear within `window_chars` of the match (chars before + chars after)
- `exclude_nearby_keyword`: match is dropped if the keyword IS present in the window. Supports optional `direction: "before" | "after" | "around"` (default `around`) to restrict which side of the match is checked. Used by Vibe V50/V55 to catch async auth checks that are missing an `await` on the same line.

**value_suppressions:** evaluated on the matched text (or capture group
if `capture_group` is set). If any suppression matches, the finding is
dropped.

- `placeholder_fragments`: case-insensitive contains-any against a list
- `regex_match`: if the value matches this regex, drop
- `length_gt`: drop if value length exceeds max

**capture_group:** if the rule extracts a specific portion of the
match (e.g., the actual key value from `api_key = "..."`), specify
which group holds it. Value suppressions and entropy checks operate
on the capture, not the full match.

**match_once:** when `true`, the runner emits at most one finding per
file even if the regex matches multiple times. Mirrors desktop's
common `break` pattern in framework / deploy / privacy scanners where
the rule answers "does this file have the problem anywhere?" and the
exact match count isn't meaningful.

### Rule kind: `entropy`

Shannon-entropy-based detection. Used for catch-all high-entropy
string detection where no specific regex pattern applies.

```jsonc
{
  "kind": "entropy",
  "id": "S99",
  "name": "High-Entropy String (Potential Secret)",
  "severity": "High",
  "note_template": "Entropy {entropy:.2} bits/char on {length}-char string. Likely a key or token.",
  "remediation": "If secret, move to env vars. If not, suppress this finding.",
  "capture_regex": "['\"]([A-Za-z0-9+/=_-]{30,})['\"]",
  "min_entropy_bits": 5.0,
  "max_length": 500,
  "shape_exclusions": [
    "^[a-f0-9]{40}$"                    // git SHA-1
  ],
  "scope": {
    "exclude_extensions": ["map", "min.js"]
  },
  "value_suppressions": [
    { "type": "placeholder_fragments", "fragments": ["example", "test", "xxxx"] }
  ]
}
```

Runner flow:

1. Apply `scope` to decide if the file is in scope
2. Run `capture_regex` to extract candidate strings (group 1)
3. For each candidate:
   - Skip if length > `max_length`
   - Skip if any `shape_exclusions` regex matches
   - Skip if any `value_suppressions` matches
   - Compute Shannon entropy
   - If entropy >= `min_entropy_bits`, emit finding with note formatted from `note_template`

`note_template` supports `{entropy}`, `{entropy:.2}` (2 decimals), `{length}`.

### Rule kind: `ast`

Tree-sitter query rule. Used when regex is insufficient — e.g.,
distinguishing a function call from a method call on an object,
or finding patterns across multiple statements.

```jsonc
{
  "kind": "ast",
  "id": "OW01",
  "name": "eval() on user input",
  "severity": "Critical",
  "note": "User-controlled string passed to eval() — arbitrary code execution.",
  "remediation": "Never use eval() on user input. Use structured parsers (JSON.parse, etc).",
  "language": "javascript",
  "query": "(call_expression function: (identifier) @fn (#eq? @fn \"eval\")) @match",
  "capture_name": "match",
  "scope": { "extensions": ["js", "jsx", "ts", "tsx"] }
}
```

| Field | Required | Description |
|---|---|---|
| `language` | ✓ | Tree-sitter grammar name. Must be loadable on both platforms. |
| `query` | ✓ | Tree-sitter S-expression query. Identical on Rust and web. |
| `capture_name` | – | Which named capture to report as the finding location. Defaults to `match`. |

AST rules are introduced in Sprint 6 (web-tree-sitter integration). v1
of the schema reserves the shape but web runner v1 skips AST rules
with a warning if any are present.

---

## Finding shape

A rule match produces a `Finding` with this shape — identical to the
desktop `Finding` struct in `src-tauri/src/engine/mod.rs`:

```typescript
interface Finding {
  id: string;              // rule.id
  name: string;            // rule.name
  severity: Severity;      // rule.severity
  detection: string;       // "Static" for regex/entropy, "AST" for ast
  category: string;        // rule.category ?? pack.category
  owasp_ref: string | null;
  mobile_ref: string | null;
  file: string;            // relative path
  line: number | null;     // 1-indexed
  col: number | null;
  snippet: string | null;  // 3-line context around the match
  git_commit: null;        // always null from non-git scanners
  git_date: null;
  note: string;            // rule.note (or interpolated for entropy)
  remediation: string;     // rule.remediation
  suppressed: false;       // web scanner does not support suppressions yet
  suppression_reason: null;
  suppressed_at: null;
  scan_id: string;         // generated per scan session
}
```

---

## Validation

`shared-rules/validate.mjs` is the reference validator. It checks:

1. Every JSON pack parses cleanly
2. Every rule has required fields for its `kind`
3. Every regex compiles in JavaScript (desktop Rust validation is TODO
   until Rust build is available)
4. `scanner_id` uniqueness across packs
5. Rule `id` uniqueness within a pack

Run it from the repo root: `node shared-rules/validate.mjs`

---

## Drift management

Until v2.1 (desktop Core SDK extraction), desktop Rust keeps its
hardcoded rule tables and web TS consumes these JSON packs. The
packs are extracted from current Rust source, so they start
identical.

**Rules for managing drift during the gap:**

1. **JSON is source of truth for NEW rules.** Any rule added after
   the initial extraction goes into JSON first. Desktop Rust is
   hand-patched to match before its next alpha release.

2. **CHANGELOG entry required for every pack change.** `shared-rules/CHANGELOG.md`
   tracks rule additions, removals, and semantic changes with date
   and reason.

3. **Semver on `pack.version`.**
   - Patch (1.0.1): regex tweak, remediation wording
   - Minor (1.1.0): new rule added
   - Major (2.0.0): breaking schema change (rare)

4. **Drift audit every release.** Before each desktop or web release,
   diff the Rust hardcoded rules against the JSON pack. Reconcile.
   Logged in release notes.

5. **v2.1 Core SDK extraction closes the gap.** Desktop Rust refactors
   to `include_str!("../../shared-rules/secret.json")` + a Rust rule
   runner matching the TS runner. At that point, drift becomes
   impossible by construction.

---

## Schema changelog

- **v1 (2026-04)**: initial schema. Supports `regex`, `entropy`, `ast`
  rule kinds. AST rules reserved for Sprint 6+.
