# IOnclad Rule Packs

The canonical pre-launch security rule packs powering the [IOnclad](https://theionproject.com/ionclad/) browser scanner. **MIT licensed. Open source.**

> *"These checks cover known vulnerability patterns and common misconfigurations. They do not constitute a comprehensive penetration test, security certification, or guarantee against all possible attack vectors."*

That disclaimer is on every IOnclad scan result and now also at the top of this README. Honest scanner. The rules below are exactly what the deployed scanner runs — you can read them, copy them, fork them, contribute back, or audit them line-by-line. No proprietary detection magic, no closed-source CVE database, no surprises.

## What's in this repo

| Pack | Rules | Coverage |
|---|---|---|
| `secret.json` | 30 (29 regex + 1 entropy) | Hardcoded AWS / GitHub / Stripe / Slack / OpenAI / Anthropic / Google / Heroku / Twilio / SendGrid / etc. tokens, plus Shannon-entropy fallback for keys without provider patterns. |
| `vibe.json` | 27 | AI-generated code anti-patterns — debug flags, weak default secrets, SQL injection shapes, JWT misuse, common smells in vibe-coded prototypes. |
| `framework.json` | 36 | Express / Next.js / Django / Flask / Rails / Laravel / React / Vue framework-specific misconfigurations. |
| `deploy.json` | 38 | Production-readiness audit: TLS enforcement, DB SSL, env-var hygiene, K8s probes, source-map leakage, hardcoded ports, missing `.env.example`. |
| `privacy.json` | 13 | GDPR / CCPA / app-store basics — privacy policy presence, PII keywords, ad-network SDK usage, tracking framework usage. |
| `llm-security.json` | 23 | LLM / AI-app security — prompt injection, unsafe handling of model output, system-prompt leakage, missing input/output limits, and tool/function-call risks in LLM integrations. |

**Total: 6 packs, 167 rules, schema v1.1.0.**

## Schema

Pack format is described in [`SCHEMA.md`](./SCHEMA.md). TypeScript types in [`schema.ts`](./schema.ts). Three rule kinds:

- **`regex`** — pattern matching with optional context filters (`exclude_contains`, `nearby_keyword`, `exclude_nearby_keyword`), severity gating, scope rules, and value/shape suppression.
- **`entropy`** — Shannon-entropy detection over captured strings, with shape exclusions (skip git SHAs, sha512 integrity hashes, UUIDs) and path exclusions (skip lockfiles).
- **`ast`** — placeholder for tree-sitter structural analysis (used by the desktop build, web build skips with a warning).

## Validate

Zero-dependency validator in [`validate.mjs`](./validate.mjs). Requires Node 18+:

```bash
node validate.mjs
```

Output:

```
IOnclad rule pack validator
Found 6 pack(s): deploy.json, framework.json, llm-security.json, privacy.json, secret.json, vibe.json
OK 6 pack(s), 167 rule(s) validated cleanly
```

## Try the rules without writing code

Just drop a folder at **[theionproject.com/ionclad/scan](https://theionproject.com/ionclad/scan/)**. The browser scanner runs these exact rules client-side — no upload, no signup, no account.

Works in any modern browser. File System Access API on Chromium (Chrome / Edge / Arc / Brave / Opera). Zip upload fallback on Firefox / Safari / iOS Safari.

## Contributing

PRs welcome, especially for:

1. **New provider patterns** — token formats for SaaS APIs not yet covered
2. **Framework rules** — known-bad configurations for the 8 frameworks above (or new frameworks)
3. **AI-code anti-patterns** — characteristic smells from Cursor / v0 / Bolt / Claude / GPT-generated code
4. **False-positive reductions** — `exclude_contains`, `value_suppressions`, `shape_exclusions` refinements

Please:
- Validate locally before submitting (`node validate.mjs`)
- Keep `severity` honest — only mark `Critical` for true ship-blockers
- Bump the pack `version` and add a `CHANGELOG.md` entry
- Justify new rules with an example real-world finding

Issues for FP reports are also welcome. The honest-scanner brand commits to being upfront about coverage limits, so `closed: not a bug, refining detection scope` is a valid resolution path.

## License

MIT — see [`LICENSE`](./LICENSE). Copy these rules into your own scanner, fork the schema, ship a competing product. We'll cheer you on. The product around the rules — scanner UI, desktop app, brand, distribution — is what IOnclad sells.

## Related

- [theionproject.com/ionclad](https://theionproject.com/ionclad/) — landing page
- [theionproject.com/ionclad/scan](https://theionproject.com/ionclad/scan/) — live browser scanner
- [theionproject.com/ionclad/download](https://theionproject.com/ionclad/download/) — desktop installer (Windows v1.0)

## Security disclosures

Found a vulnerability or detection bypass in a deployed IOnclad app (not in these rules — actual security holes in the binary)? Email **security@theionproject.com**. Please don't open public issues for security disclosures.

For rule-pack false positives, false negatives, or coverage gaps — public GitHub issues are perfect.
