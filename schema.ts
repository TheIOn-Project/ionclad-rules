// ═══════════════════════════════════════════════════════════════════════
// IOnclad Shared Rule Schema — v1
// Authoritative TypeScript definitions. See SCHEMA.md for design notes.
//
// CONSUMERS:
//   - ionclad-web/src/engine/ruleRunner.ts  (live in v2.0.0-beta)
//   - src-tauri/src/engine/rules/           (planned v2.1 Core SDK extraction)
//
// COMPATIBILITY:
//   Any change to this file requires a pack-version bump and a drift audit
//   against existing rule packs. Never change field semantics silently.
// ═══════════════════════════════════════════════════════════════════════

export const SCHEMA_VERSION = "1.0.0" as const;

// ─── Core enums ─────────────────────────────────────────────────────────

export type Severity = "Critical" | "High" | "Medium" | "Low";

export type Detection = "Static" | "AST" | "Entropy";

/**
 * Canonical scanner identities — must match:
 *  - src-tauri/src/engine/categories.rs :: scanner::*
 *  - src/data/scanners.ts :: SCANNERS[].id
 */
export type ScannerId =
  | "secrets"
  | "vibe-pack"
  | "framework"
  | "deploy"
  | "privacy"
  | "owasp-web"
  | "session-auth"
  | "api-surface"
  | "third-party"
  | "a11y"
  | "git-history"
  | "iac"
  | "email"
  | "pwa"
  | "graphql"
  | "ios";

/**
 * Canonical finding categories — must match cat::* in categories.rs.
 * Rules may emit any category; this union is the currently-known set.
 */
export type Category =
  | "secrets"
  | "vibe"
  | "framework"
  | "deploy"
  | "privacy"
  | "owasp-web"
  | "session-auth"
  | "api-surface"
  | "third-party"
  | "a11y"
  | "git-history"
  | "iac"
  | "email"
  | "pwa"
  | "graphql"
  | "ios"
  | (string & {}); // allow unknown categories with autocomplete on known ones

// ─── File scoping ───────────────────────────────────────────────────────

/**
 * Per-rule file scope. All filters combine as AND.
 * When a field is omitted, that filter is skipped.
 * When `extensions` / `path_suffixes` / `path_patterns` are all omitted,
 * the rule runs against all text files.
 */
export interface FileScope {
  /** Match if the file's extension (no leading dot) appears in this list. */
  extensions?: string[];
  /** Match if the file path ends with any of these strings. */
  path_suffixes?: string[];
  /** Glob-style patterns (**​/foo, *.min.js) — basic support in v1. */
  path_patterns?: string[];
  /** If any match, the file is excluded regardless of the positive filters. */
  exclude_extensions?: string[];
  exclude_path_suffixes?: string[];
  exclude_path_patterns?: string[];
}

// ─── Context filters ────────────────────────────────────────────────────

/**
 * Post-match filter. Runs after regex match succeeds; if filter rejects,
 * the match is discarded (no finding emitted).
 */
export type ContextFilter =
  | {
      type: "nearby_keyword";
      /**
       * At least one of these keywords must appear within `window_chars`
       * of the match. Case-insensitive substring search.
       */
      keywords: string[];
      /** window_chars chars before match start + window_chars chars after match end. */
      window_chars: number;
    }
  | {
      /**
       * Inverse: finding is dropped if ANY listed keyword appears in the
       * window. Used e.g. to reject async-auth matches whose preceding
       * line already contains `await` or `return`.
       */
      type: "exclude_nearby_keyword";
      keywords: string[];
      window_chars: number;
      /**
       * Where to look relative to the match.
       *   "before" — only the window_chars chars before match_start
       *   "after"  — only the window_chars chars after match_end
       *   "around" — both sides (default)
       */
      direction?: "before" | "after" | "around";
    };

// ─── Value suppressions ─────────────────────────────────────────────────

/**
 * Filters applied to the matched text (or capture group if capture_group set).
 * If ANY suppression matches, the finding is dropped.
 */
export type ValueSuppression =
  | {
      type: "placeholder_fragments";
      /** Case-insensitive contains-any. */
      fragments: string[];
    }
  | {
      type: "regex_match";
      /** If this regex matches the value, drop. */
      pattern: string;
      flags?: string;
    }
  | {
      type: "length_gt";
      max: number;
    };

// ─── Rule common fields ─────────────────────────────────────────────────

interface RuleBase {
  id: string;
  name: string;
  severity: Severity;
  note: string;
  remediation: string;
  /** Overrides pack.category when set. */
  category?: Category;
  owasp_ref?: string | null;
  mobile_ref?: string | null;
  scope?: FileScope;
}

// ─── Rule kinds ─────────────────────────────────────────────────────────

export interface RegexRule extends RuleBase {
  kind: "regex";
  /** Regex pattern. Must work in both Rust `regex` and JS `RegExp`. */
  regex: string;
  /** Regex flags — "i", "m", "s", or combinations. "g" is implied by the runner. */
  regex_flags?: string;
  /** If set, extract this capture group as the reportable value for suppressions. */
  capture_group?: number;
  /** Whole-file pre-check: content must contain ALL of these (case-insensitive). */
  require_contains?: string[];
  /** Whole-file pre-check: content must contain NONE of these (case-insensitive). */
  exclude_contains?: string[];
  context_filter?: ContextFilter;
  value_suppressions?: ValueSuppression[];
  /**
   * When true, emit at most ONE finding per file even if the regex matches
   * multiple times. Mirrors the desktop `break` pattern used by framework /
   * deploy / privacy scanners that report one finding per file regardless
   * of match count.
   */
  match_once?: boolean;
}

export interface EntropyRule extends RuleBase {
  kind: "entropy";
  /**
   * Regex that extracts candidate strings. Capture group 1 is the candidate.
   * e.g., `['"]([A-Za-z0-9+/=_-]{30,})['"]` extracts quoted high-char-class strings.
   */
  capture_regex: string;
  /** Minimum Shannon entropy in bits/char for a candidate to be reported. */
  min_entropy_bits: number;
  /** Skip candidates longer than this. */
  max_length?: number;
  /** Skip candidates matching any of these regexes (e.g., git-sha shape). */
  shape_exclusions?: string[];
  value_suppressions?: ValueSuppression[];
  /**
   * `note` may omit the `{entropy}` / `{length}` placeholders; they're
   * interpolated at emit time. For backward compat, `note_template` is
   * treated as an alias for `note` when `note` is absent.
   */
  note_template?: string;
}

export interface AstRule extends RuleBase {
  kind: "ast";
  language:
    | "javascript"
    | "typescript"
    | "python"
    | "java"
    | "go"
    | "rust"
    | "swift"
    | "kotlin";
  /** Tree-sitter S-expression query. Identical on both runners. */
  query: string;
  /** Which named capture to report as the finding location. Default: "match". */
  capture_name?: string;
}

export type Rule = RegexRule | EntropyRule | AstRule;

// ─── Pack ───────────────────────────────────────────────────────────────

export interface RulePack {
  /** Schema version reference — pinned to SCHEMA.md anchor. */
  $schema?: string;
  scanner_id: ScannerId;
  scanner_name: string;
  scanner_description: string;
  /** Default category for rules in this pack. Rules may override. */
  category: Category;
  /** Pack version — semver. Bump on any rule change. */
  version: string;
  /** If true, runs on every scan regardless of app type detection. */
  overlay: boolean;
  rules: Rule[];
}

// ─── Finding shape (emitted by the runner) ──────────────────────────────

/**
 * The shape a rule match produces. Field-for-field identical to the
 * desktop Rust `Finding` struct in src-tauri/src/engine/mod.rs.
 */
export interface Finding {
  id: string;
  name: string;
  severity: Severity;
  detection: Detection;
  category: string;
  owasp_ref: string | null;
  mobile_ref: string | null;
  file: string;
  line: number | null;
  col: number | null;
  snippet: string | null;
  git_commit: string | null;
  git_date: string | null;
  note: string;
  remediation: string;
  suppressed: boolean;
  suppression_reason: string | null;
  suppressed_at: string | null;
  scan_id: string;
}

// ─── Type guards for runtime rule dispatch ──────────────────────────────

export const isRegexRule = (r: Rule): r is RegexRule => r.kind === "regex";
export const isEntropyRule = (r: Rule): r is EntropyRule => r.kind === "entropy";
export const isAstRule = (r: Rule): r is AstRule => r.kind === "ast";
