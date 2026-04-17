# Adopting the Hive Documentation Methodology for ssl-toolbox

**Date:** 2026-04-17
**Status:** Approved
**Source:** Methodology template from [ForkTheGhost/hive](https://github.com/ForkTheGhost/hive)
**Scope:** Full adoption — spec-first, TDD-enforced, PR-gated

---

## Problem

ssl-toolbox has grown from a single-binary utility into a multi-crate workspace with a pluggable CA integration, feature-gated builds, and a security-sensitive surface (TLS verification, key/CSR generation, PFX handling). Current documentation is a single `README.md` and a `USER_MANUAL.md`. There is no authoritative design spec, no change log, no contributor workflow — so:

- Behavior is only defined by code and tests, not by a human-readable contract
- Regressions in cipher scanning, PFX legacy profiles, and Sectigo OAuth have no changelog trail
- Contributors have no gate for when a PR is or isn't ready to merge
- Future CA plugin authors have no spec to implement against

The hive methodology solves this with a one-directional workflow: `ARCHITECTURE.md → Tests → Code`. This spec documents how we adopt it.

---

## Methodology Contract (Option A — Full Adopt)

### The Workflow Rule

```
ARCHITECTURE.md (spec) → Tests (encode spec) → Code (satisfies tests)
```

- Every feature or behavioral change requires an `ARCHITECTURE.md` update **in the same PR**.
- Tests are written against the spec, not the code. If a test fails, either the code is wrong or the test is wrong; if the test is wrong, the spec is wrong — fix the spec, then the test, then the code. Never modify a test just to make code pass.
- Every PR references a GitHub Issue and adds a `CHANGELOG.md` entry under `[Unreleased]`.

### CI Gates

All PRs must pass:
- `cargo test --workspace`
- `cargo clippy --workspace -- -D warnings`
- `cargo fmt --all --check`
- `cargo check -p ssl-toolbox --no-default-features` (sans-Sectigo build)

### The Aphorism

> If it's not in ARCHITECTURE.md, it doesn't have a spec. If it doesn't have a spec, it can't have tests. If it can't have tests, it doesn't ship.

---

## Deliverables

Four files, authored or updated in this adoption:

1. **`ARCHITECTURE.md`** — new, authoritative spec (~500-700 lines)
2. **`CONTRIBUTING.md`** — new, hive TDD flow adapted to Rust/cargo
3. **`CHANGELOG.md`** — new, seeded from tag history (v1.0.0 → v2.0.1) + `[Unreleased]`
4. **`README.md`** — updated: replace inline architecture with pointer, add Documentation Flow + See Also

---

## 1. ARCHITECTURE.md

**Purpose:** The single source of truth for how ssl-toolbox works. Every feature and behavioral rule is defined here before it exists in code. Tests encode this spec. PRs updating behavior must update this file in the same changeset.

### Section Outline

1. **Core Concepts** — What ssl-toolbox is; the workspace as four crates; `CaPlugin` trait as the extension seam
2. **Workspace & Crate Boundaries**
   - `ssl-toolbox` (CLI binary): clap commands, interactive menu, display/formatting
   - `ssl-toolbox-core` (library): key/CSR gen, PFX, TLS, SMTP, validation, convert, config
   - `ssl-toolbox-ca` (trait crate): `CaPlugin`, `CertProfile`, `SubmitOptions`
   - `ssl-toolbox-ca-sectigo` (feature-gated impl): Sectigo SCM implementation
   - Dependency rules: `ssl-toolbox-core` has no CA awareness; CLI depends on core + (optionally) CA crates
   - Feature gate matrix: `sectigo` feature on/off, impact on each crate
3. **Configuration Model**
   - Five-layer resolution order (later wins):
     1. Compiled defaults (empty strings)
     2. `~/.ssl-toolbox/*.json` (user-level)
     3. `./.ssl-toolbox/*.json` (project-level)
     4. Environment variables / `.env`
     5. CLI flags
   - File contract: `config.json` (CSR defaults), `sectigo.json` (CA plugin settings), `.env` (secrets only — never in JSON)
   - `init` command behavior; `--global` vs project init
4. **Key & CSR Generation**
   - RSA-2048 (rationale); AES-256-CBC encryption for private keys (OpenSSL compat)
   - SAN schema: DNS, IP, email, URI
   - OpenSSL `.cnf` extraction from existing cert or CSR (round-trip contract)
5. **PFX / PKCS12**
   - Modern profile: AES-256-SHA256
   - Legacy profile: TripleDES-SHA1 (opt-in via `--legacy`)
   - Conversion model (modern ↔ legacy)
   - Viewer output contract (what `view-pfx` must show)
6. **TLS Verification**
   - Probe contracts per protocol: HTTPS, LDAPS, SMTP-STARTTLS
   - Report fields: negotiated cipher, TLS version support (1.0–1.3), hostname match, expiry, chain validation
   - Full-scan model: which cipher suites are locally testable (HTTPS + LDAPS)
   - `--no-verify` semantics (skip chain validation, keep other checks)
7. **Format Tools**
   - Convert matrix: PEM ↔ DER ↔ Base64
   - Auto-detect algorithm: magic bytes, PEM headers, fallback
8. **CA Plugin Trait**
   - `CaPlugin` interface: required methods, error surface
   - `CertProfile`, `SubmitOptions` shapes
   - How a new CA plugin would be implemented
9. **Sectigo Integration**
   - OAuth client-credentials flow; `SCM_CLIENT_ID` / `SCM_CLIENT_SECRET` env vars
   - Endpoints: list profiles, submit, collect
   - Collection formats: pem, chain, pkcs7
   - Error surface and retry behavior
10. **Interactive Workflow & Persistent State**
    - Menu model (cliclack-driven)
    - Active profile selection
    - Recent jobs / artifacts tracking (`.ssl-toolbox/` workspace state)
11. **Threat Model**
    - What ssl-toolbox protects against: typos in CSR, wrong format, weak defaults, MITM on verification
    - What it does NOT protect against: compromised host, malicious system libc, key exfiltration
    - Secret handling rules: never logged, never printed, never in JSON
    - Vendored OpenSSL: trust boundary, no FIPS mode
12. **Design Principles** (numbered, 8-10 rules)
    - Modern crypto default, legacy opt-in only
    - Feature-gate all CA dependencies
    - Never print secrets (keys, tokens, passwords)
    - Vendored OpenSSL — no system OpenSSL dependency
    - CLI and interactive menu must reach feature parity
    - Config layering: CLI > env > project > user > defaults (no exceptions)
    - Single-binary distribution (no runtime deps)
    - Test against the spec, not the implementation
13. **Known Tradeoffs**
    - Vendored OpenSSL blocks FIPS mode — accepted for portability
    - AES-CBC (not GCM) for encrypted keys — accepted for OpenSSL CLI compatibility
    - Cipher scan is "locally testable" only — system OpenSSL may expose more
    - `--legacy` PFX uses deprecated crypto — accepted for legacy Windows/Java compat

---

## 2. CONTRIBUTING.md

**Purpose:** Encode the TDD/spec-first workflow as a contributor contract. Mirror hive's structure; swap the Node tooling for Rust/cargo.

### Section Outline

1. **Issues** — all features and bug reports tracked as GitHub Issues before work begins. Issues must identify test gaps, acceptance criteria, and whether ARCHITECTURE.md needs updating.
2. **Test-Driven Development**
   - One-directional flow: `ARCHITECTURE.md → Tests → Code`
   - Red / Green / Refactor cycle
   - Rules:
     - Issues identify test gaps
     - CI must pass (`cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --all --check`, `cargo check -p ssl-toolbox --no-default-features`)
     - No masked signals: exact assertions, not weak upper-bound checks. Prefer `assert_eq!(result, Ok(expected_value))` over `assert!(result.is_ok())`.
     - Spec is authoritative: fix spec → tests → code, never the reverse
   - Local pre-push: enable `.githooks/pre-push` via `git config core.hooksPath .githooks`
3. **Pull Requests**
   - All changes via PR against `main`; no direct commits
   - PR requirements:
     - Reference the issue (`Closes #N` or `Ref #N`)
     - Include a `CHANGELOG.md` entry under `[Unreleased]`
     - Update `ARCHITECTURE.md` in the same PR if behavior changes
     - All review comments acknowledged and addressed before merge
     - CI green
     - Feature-flag rule: any PR touching `ssl-toolbox-ca-sectigo` or the `sectigo` feature must also pass `cargo check -p ssl-toolbox --no-default-features`
4. **CHANGELOG Format**

   Each PR adds an entry under `## [Unreleased]`:

   ```markdown
   ### <type>: <short description> (`<commit-sha>`) — closes #N

   One or two sentences describing what changed and why.
   Reference [#N](https://github.com/trepidity/SSL-Toolbox/issues/N) for full context.
   ```

   Types: `feat`, `fix`, `docs`, `chore`, `decision`.
   - `decision` entries document architectural or policy choices with no direct code change — preserved long-term.

---

## 3. CHANGELOG.md

**Purpose:** Authoritative record of notable changes. Seeded retroactively from tag history; maintained going forward via `[Unreleased]` on every PR.

### Seeding Strategy

- Top of file: `## [Unreleased]` (empty for now)
- Back-fill one section per tagged release, newest first: `v2.0.1`, `v2.0.0`, `v1.0.9` … `v1.0.0` (12 releases)
- Each back-filled section uses `git log <prev-tag>..<tag>` to enumerate commits, condensed to hive-format entries (`feat:` / `fix:` / `docs:` / `chore:`) with SHAs where meaningful
- For older releases (pre-v1.0.2) where commit messages are sparser, use a single condensed summary entry rather than fabricating detail
- No `decision:` entries initially; those accumulate going forward

### Format

Same as hive's:

```markdown
## vX.Y.Z — YYYY-MM-DD

### feat: short description (`<sha>`)

One or two sentences of context.
```

---

## 4. README.md (Update)

**Purpose:** Keep as the human-readable entry point. Keep all the user-facing content that already works. Add the hive methodology links.

### Preserve (no changes)

- Top blurb and Features table
- Quick Start
- Installation (Build from Source, Pre-built Binaries)
- Configuration
- Command Reference
- Development
- License

### Replace

- The inline **Architecture** section — replace with a short pointer paragraph that defers to `ARCHITECTURE.md` as the authoritative spec.

### Add

- **Documentation Flow** section (just before Contributing) — reproduce hive's diagram and the aphorism:
  > If it's not in ARCHITECTURE.md, it doesn't have a spec. If it doesn't have a spec, it can't have tests. If it can't have tests, it doesn't ship.
- **Contributing** subsection — point at `CONTRIBUTING.md`
- **See Also** bottom section — links to `ARCHITECTURE.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `docs/USER_MANUAL.md`

---

## Execution Order

The four files have no content dependencies on each other beyond filename references — README.md links to the others by name, but doesn't quote their content. They can be authored in parallel by independent agents.

1. Commit this spec
2. Dispatch four parallel agents, one per file
3. Review the resulting PR-ready state; spot-fix cross-references if needed
4. Run CI gates locally; address any friction before declaring adoption complete

---

## Success Criteria

- `ARCHITECTURE.md` exists at repo root, covers all 13 sections, is internally consistent, and matches current ssl-toolbox behavior (spec reflects reality, not aspiration)
- `CONTRIBUTING.md` exists at repo root, follows hive's structure with Rust tooling swaps
- `CHANGELOG.md` exists at repo root with `[Unreleased]` + all 12 tagged releases back-filled
- `README.md` retains all current user-facing content; inline Architecture replaced with a pointer; Documentation Flow and See Also sections added
- All four files cross-reference correctly (links resolve)
- Repository still builds: `cargo check --workspace` and `cargo check -p ssl-toolbox --no-default-features` both pass
