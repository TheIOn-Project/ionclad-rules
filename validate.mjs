#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════
// IOnclad Rule Pack Validator
//
// Validates every JSON file under shared-rules/ against the schema.
// Zero runtime dependencies — just Node.js stdlib.
//
// Usage:
//   node shared-rules/validate.mjs
//   node shared-rules/validate.mjs --pack secret.json
//   node shared-rules/validate.mjs --verbose
//
// Exit codes:
//   0 = all packs valid
//   1 = validation failures
//   2 = internal error (bad script args, etc)
// ═══════════════════════════════════════════════════════════════════════

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ─── ANSI colors (disabled if not a TTY) ───────────────────────────────

const supportsColor = process.stdout.isTTY && process.env.NO_COLOR !== "1";
const c = (code) => (s) => supportsColor ? `\x1b[${code}m${s}\x1b[0m` : s;
const red = c("31");
const green = c("32");
const yellow = c("33");
const dim = c("2");
const bold = c("1");

// ─── CLI args ──────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const verbose = args.includes("--verbose") || args.includes("-v");
const packFilter = (() => {
  const i = args.indexOf("--pack");
  return i >= 0 ? args[i + 1] : null;
})();

// ─── Validation logic ──────────────────────────────────────────────────

const VALID_SEVERITIES = new Set(["Critical", "High", "Medium", "Low"]);
const VALID_KINDS = new Set(["regex", "entropy", "ast"]);
const VALID_SUPPRESSION_TYPES = new Set([
  "placeholder_fragments",
  "regex_match",
  "length_gt",
]);
const VALID_CONTEXT_FILTER_TYPES = new Set([
  "nearby_keyword",
  "exclude_nearby_keyword",
]);
const VALID_AST_LANGUAGES = new Set([
  "javascript",
  "typescript",
  "python",
  "java",
  "go",
  "rust",
  "swift",
  "kotlin",
]);

class Validator {
  constructor() {
    this.errors = [];
    this.warnings = [];
    this.seenScannerIds = new Set();
  }

  error(where, msg) {
    this.errors.push({ where, msg });
  }

  warn(where, msg) {
    this.warnings.push({ where, msg });
  }

  validatePack(path, pack) {
    const w = `[${path}]`;

    // Top-level required fields
    for (const field of [
      "scanner_id",
      "scanner_name",
      "scanner_description",
      "category",
      "version",
      "rules",
    ]) {
      if (pack[field] === undefined || pack[field] === null) {
        this.error(w, `missing required field: ${field}`);
      }
    }

    if (typeof pack.scanner_id === "string") {
      if (this.seenScannerIds.has(pack.scanner_id)) {
        this.error(w, `duplicate scanner_id "${pack.scanner_id}" across packs`);
      }
      this.seenScannerIds.add(pack.scanner_id);
    }

    if (typeof pack.overlay !== "boolean") {
      this.error(w, `"overlay" must be boolean, got ${typeof pack.overlay}`);
    }

    if (!Array.isArray(pack.rules)) {
      this.error(w, `"rules" must be an array`);
      return;
    }

    // Semver-ish check on version
    if (typeof pack.version === "string") {
      if (!/^\d+\.\d+\.\d+(-[\w.]+)?$/.test(pack.version)) {
        this.warn(w, `version "${pack.version}" is not strict semver`);
      }
    }

    // Rule IDs unique within pack
    const seenIds = new Set();
    pack.rules.forEach((rule, idx) => {
      const rw = `${w} rules[${idx}]${rule.id ? ` (id=${rule.id})` : ""}`;

      if (typeof rule.id !== "string" || rule.id.length === 0) {
        this.error(rw, `missing or empty "id"`);
      } else if (seenIds.has(rule.id)) {
        this.error(rw, `duplicate rule id "${rule.id}" within pack`);
      } else {
        seenIds.add(rule.id);
      }

      this.validateRule(rw, rule);
    });
  }

  validateRule(w, rule) {
    // Common fields
    for (const field of ["name", "severity", "note", "remediation", "kind"]) {
      if (typeof rule[field] !== "string" || rule[field].length === 0) {
        this.error(w, `missing or empty required field: ${field}`);
      }
    }

    if (!VALID_SEVERITIES.has(rule.severity)) {
      this.error(
        w,
        `invalid severity "${rule.severity}" — must be one of ${[...VALID_SEVERITIES].join(", ")}`,
      );
    }

    if (!VALID_KINDS.has(rule.kind)) {
      this.error(
        w,
        `invalid kind "${rule.kind}" — must be one of ${[...VALID_KINDS].join(", ")}`,
      );
      return;
    }

    if (rule.scope) this.validateScope(w, rule.scope);

    switch (rule.kind) {
      case "regex":
        this.validateRegexRule(w, rule);
        break;
      case "entropy":
        this.validateEntropyRule(w, rule);
        break;
      case "ast":
        this.validateAstRule(w, rule);
        break;
    }
  }

  validateScope(w, scope) {
    const stringArrayFields = [
      "extensions",
      "path_suffixes",
      "path_patterns",
      "exclude_extensions",
      "exclude_path_suffixes",
      "exclude_path_patterns",
    ];
    for (const f of stringArrayFields) {
      if (scope[f] === undefined) continue;
      if (!Array.isArray(scope[f])) {
        this.error(w, `scope.${f} must be an array`);
        continue;
      }
      for (const s of scope[f]) {
        if (typeof s !== "string") {
          this.error(w, `scope.${f} must contain only strings`);
          break;
        }
      }
    }
  }

  validateRegexRule(w, rule) {
    if (typeof rule.regex !== "string" || rule.regex.length === 0) {
      this.error(w, `regex rule missing "regex"`);
      return;
    }

    // Flags
    const flags = rule.regex_flags ?? "";
    if (typeof flags !== "string" || /[^imsu]/.test(flags)) {
      this.error(w, `regex_flags "${flags}" contains unsupported flag`);
    }

    // Compile in JS regex engine as a portability check
    try {
      new RegExp(rule.regex, flags);
    } catch (e) {
      this.error(w, `regex does not compile in JS: ${e.message}`);
    }

    // Warn on known Rust-regex-incompatible features
    if (/\(\?=|\(\?!|\(\?<=|\(\?<!/.test(rule.regex)) {
      this.warn(
        w,
        `regex uses lookahead/lookbehind — NOT supported by Rust's regex crate. Pattern will fail on desktop runner.`,
      );
    }
    if (/\\(\d)/.test(rule.regex)) {
      this.warn(
        w,
        `regex uses backreferences (\\N) — NOT supported by Rust's regex crate.`,
      );
    }

    if (rule.capture_group !== undefined) {
      if (!Number.isInteger(rule.capture_group) || rule.capture_group < 0) {
        this.error(w, `capture_group must be a non-negative integer`);
      }
    }

    if (rule.require_contains !== undefined) {
      if (!Array.isArray(rule.require_contains)) {
        this.error(w, `require_contains must be an array of strings`);
      }
    }
    if (rule.exclude_contains !== undefined) {
      if (!Array.isArray(rule.exclude_contains)) {
        this.error(w, `exclude_contains must be an array of strings`);
      }
    }

    if (rule.context_filter) {
      if (!VALID_CONTEXT_FILTER_TYPES.has(rule.context_filter.type)) {
        this.error(
          w,
          `context_filter.type "${rule.context_filter.type}" is not a known type`,
        );
      }
      if (
        rule.context_filter.type === "nearby_keyword" ||
        rule.context_filter.type === "exclude_nearby_keyword"
      ) {
        if (
          !Array.isArray(rule.context_filter.keywords) ||
          rule.context_filter.keywords.length === 0 ||
          !rule.context_filter.keywords.every((k) => typeof k === "string") ||
          !Number.isInteger(rule.context_filter.window_chars)
        ) {
          this.error(
            w,
            `context_filter ${rule.context_filter.type} requires "keywords" (non-empty string array) and "window_chars" (int)`,
          );
        }
      }
      if (rule.context_filter.type === "exclude_nearby_keyword") {
        if (
          rule.context_filter.direction !== undefined &&
          !["before", "after", "around"].includes(rule.context_filter.direction)
        ) {
          this.error(
            w,
            `context_filter.direction must be "before" | "after" | "around"`,
          );
        }
      }
    }

    if (rule.match_once !== undefined && typeof rule.match_once !== "boolean") {
      this.error(w, `match_once must be boolean`);
    }

    if (rule.value_suppressions)
      this.validateSuppressions(w, rule.value_suppressions);
  }

  validateEntropyRule(w, rule) {
    if (typeof rule.capture_regex !== "string") {
      this.error(w, `entropy rule missing "capture_regex"`);
    } else {
      try {
        new RegExp(rule.capture_regex);
      } catch (e) {
        this.error(w, `capture_regex does not compile in JS: ${e.message}`);
      }
    }
    if (
      typeof rule.min_entropy_bits !== "number" ||
      rule.min_entropy_bits < 0
    ) {
      this.error(
        w,
        `entropy rule requires "min_entropy_bits" as a non-negative number`,
      );
    }
    if (rule.max_length !== undefined && !Number.isInteger(rule.max_length)) {
      this.error(w, `max_length must be an integer`);
    }
    if (rule.shape_exclusions !== undefined) {
      if (!Array.isArray(rule.shape_exclusions)) {
        this.error(w, `shape_exclusions must be an array of regex strings`);
      } else {
        rule.shape_exclusions.forEach((re, i) => {
          try {
            new RegExp(re);
          } catch (e) {
            this.error(
              w,
              `shape_exclusions[${i}] does not compile: ${e.message}`,
            );
          }
        });
      }
    }
    if (rule.value_suppressions)
      this.validateSuppressions(w, rule.value_suppressions);
  }

  validateAstRule(w, rule) {
    if (!VALID_AST_LANGUAGES.has(rule.language)) {
      this.error(
        w,
        `unsupported AST language "${rule.language}" — must be one of ${[...VALID_AST_LANGUAGES].join(", ")}`,
      );
    }
    if (typeof rule.query !== "string" || rule.query.length === 0) {
      this.error(w, `AST rule missing "query"`);
    }
    // Tree-sitter query validation happens at runtime in the runner.
    this.warn(
      w,
      `AST rule detected — web runner v1 skips these. Activated in Sprint 6.`,
    );
  }

  validateSuppressions(w, list) {
    if (!Array.isArray(list)) {
      this.error(w, `value_suppressions must be an array`);
      return;
    }
    list.forEach((s, i) => {
      if (!VALID_SUPPRESSION_TYPES.has(s.type)) {
        this.error(
          w,
          `value_suppressions[${i}].type "${s.type}" is not a known type`,
        );
        return;
      }
      if (s.type === "placeholder_fragments") {
        if (!Array.isArray(s.fragments)) {
          this.error(
            w,
            `placeholder_fragments suppression requires "fragments" array`,
          );
        }
      } else if (s.type === "regex_match") {
        try {
          new RegExp(s.pattern, s.flags ?? "");
        } catch (e) {
          this.error(
            w,
            `value_suppressions[${i}] regex does not compile: ${e.message}`,
          );
        }
      } else if (s.type === "length_gt") {
        if (!Number.isInteger(s.max)) {
          this.error(w, `length_gt suppression requires "max" as integer`);
        }
      }
    });
  }
}

// ─── Main ──────────────────────────────────────────────────────────────

function main() {
  const rulesDir = __dirname;
  const files = readdirSync(rulesDir).filter(
    (f) =>
      f.endsWith(".json") &&
      f !== "pack-meta.json" &&
      f !== "guidance.json" && // proactive-guidance data table, not a scanner rule pack
      (!packFilter || f === packFilter),
  );

  if (files.length === 0) {
    console.log(yellow(`No rule packs found in ${rulesDir}`));
    process.exit(0);
  }

  const v = new Validator();

  console.log(bold(`IOnclad rule pack validator`));
  console.log(dim(`Scanning ${rulesDir}`));
  console.log(dim(`Found ${files.length} pack(s): ${files.join(", ")}`));
  console.log();

  let totalRules = 0;

  for (const file of files) {
    const path = join(rulesDir, file);
    let pack;
    try {
      const raw = readFileSync(path, "utf8");
      pack = JSON.parse(raw);
    } catch (e) {
      v.error(`[${file}]`, `JSON parse error: ${e.message}`);
      continue;
    }
    v.validatePack(file, pack);
    if (Array.isArray(pack.rules)) {
      totalRules += pack.rules.length;
      if (verbose) {
        console.log(
          dim(
            `  ${file}: ${pack.rules.length} rules across kinds ` +
              [...new Set(pack.rules.map((r) => r.kind))].join("/") +
              ` (v${pack.version}, overlay=${pack.overlay})`,
          ),
        );
      }
    }
  }

  console.log();

  if (v.warnings.length > 0) {
    console.log(bold(yellow(`Warnings (${v.warnings.length}):`)));
    for (const { where, msg } of v.warnings) {
      console.log(`  ${yellow("⚠")} ${where} ${dim(msg)}`);
    }
    console.log();
  }

  if (v.errors.length > 0) {
    console.log(bold(red(`Errors (${v.errors.length}):`)));
    for (const { where, msg } of v.errors) {
      console.log(`  ${red("✗")} ${where} ${msg}`);
    }
    console.log();
    console.log(red(bold(`FAILED`)), dim(`${totalRules} rules checked`));
    process.exit(1);
  }

  console.log(
    green(bold(`OK`)),
    `${files.length} pack(s), ${totalRules} rule(s) validated cleanly`,
  );
  process.exit(0);
}

main();
