# Changelog

All notable changes to ssl-toolbox are documented here.

---

## [Unreleased]

_No unreleased changes yet._

---

## v2.0.1 — 2026-04-16

### chore: bump version to 2.0.1 (`650cd54`)

Version bumped for a packaging follow-up release after v2.0.0.

### chore: remove Windows test step from release workflow (`4c544f3`)

Dropped the Windows test stage from the release workflow to unblock the release pipeline after persistent CI friction.

---

## v2.0.0 — 2026-04-16

### feat: redesign interactive menu layout (`bd8fd8e`)

Reworked the cliclack-driven interactive menu layout for clearer navigation and workflow grouping. This is the user-visible anchor of the 2.0 release.

### chore: align release packaging with versioned artifacts (`735f12f`)

Release artifacts now follow a consistent versioned naming scheme across the supported platforms.

### chore: update lockfile for v2.0.0 (`6e15d5a`)

Refreshed `Cargo.lock` for the 2.0.0 release cut.

---

## v1.0.9 — 2026-04-16

### feat: TLS cipher scanning and endpoint normalization (`fe55570`)

Added a locally testable TLS cipher scan (HTTPS + LDAPS) and normalized endpoint parsing across verification commands. Extends the TLS verification surface beyond single-cipher probing.

---

## v1.0.8 — 2026-04-16

### feat: PFX viewer improvements and private-key summary (`000c1d6`)

Expanded the `view-pfx` output with a private key summary and richer detail formatting. Interactive result screens were also polished for consistent PFX presentation (`6506057`).

---

## v1.0.7 — 2026-04-15

### chore: add cargo fmt check to pre-push hook (`67f01f4`)

Local pre-push hook now enforces `cargo fmt --all --check` alongside existing lint gates, following a rustfmt fix in the workflow path normalizer (`7a9ed97`).

---

## v1.0.6 — 2026-04-15

### fix: upload-artifact and download-artifact Node.js 20 deprecation (`7dd6c86`)

Bumped GitHub Actions artifact actions to versions compatible with Node.js 20 to clear release workflow deprecation warnings.

---

## v1.0.5 — 2026-04-15

### fix: CI deprecation warnings and Windows test failures (`735e19b`)

Resolved a batch of CI deprecation warnings and Windows-specific test failures that were blocking release builds.

---

## v1.0.4 — 2026-04-15

### docs: update README with workflow feature and architecture alignment (`cc77b28`)

README refreshed to describe the interactive workflow feature and align the architecture summary with the current crate layout.

### fix: CI test failures from OpenSSL subject formatting differences (`f967f32`)

Tightened tests to tolerate OpenSSL subject-string formatting variations across platforms, unblocking CI on Windows and Linux runners.

---

## v1.0.3 — 2026-04-15

### chore: release v1.0.2 interactive workflow and TLS hardening (`17e450b`)

Release-tagging follow-up for the interactive workflow and TLS hardening work landed in v1.0.2.

### feat: format dashboard header with aligned labels and color (`36426bb`)

Polished the interactive dashboard header with aligned labels and color cues for readability.

---

## v1.0.2 — 2026-04-15

### feat: interactive workflow hardening and external cert validation (`8e4c90d`, `df318cc`, `9ce20f6`)

Hardened the interactive workflow replay and state handling, improved the menu and path breadcrumbs, and added external certificate validation coverage. This release consolidates the interactive-mode experience introduced in v1.0.1.

### fix: Windows build errors, clippy, and TLS chain formatting (`8f45469`, `67424a0`, `aab3487`)

Fixed Windows build errors, cleared clippy blockers for the interactive workflow release, and formatted the x509 peer chain helper. `clippy` is now enforced on push.

---

## v1.0.1 — 2026-04-14

### feat: Windows certificate manager TUI and backend expansion (`763e14d`, `491ba9b`, `dfddd4a`)

Shipped a Windows-focused certificate manager TUI with a backing expansion of the certificate surface. Includes the initial design spec and the full implementation-detail spec landed ahead of the code.

### fix: TLS chain verification handling (`00edb26`)

Corrected TLS chain verification handling so intermediate and root chain checks behave consistently across probe types.

---

## v1.0.0 — 2026-02-27

### feat: ssl-toolbox workspace, plugin architecture, and core feature set (`7c7ace8`, `ee67c01`, `884b1b7`, `53c7ae1`, `82c6ae7`, `91ad3c3`, `52130f5`)

Initial tagged release. Refactored into the `ssl-toolbox` workspace with a plugin architecture, externalized profile/config values, and consolidated the core feature set: private key and CSR generation, PFX creation and viewing (with DER support), HTTPS and LDAPS endpoint verification (library and CLI subcommands), and OpenSSL `.cnf` generation from existing certs/CSRs or from scratch. Consolidates roughly a dozen commits from early-February prototyping through the late-February cut.

### docs: rewrite README and add comprehensive user manual (`fb6ab6f`)

Rewrote the README and authored a comprehensive `USER_MANUAL.md` to document the workspace layout, configuration model, and command reference.

### chore: CI/CD, licensing, and formatting baseline (`eb95177`, `0a0a433`, `f17f492`, `ecf5b4f`, `d2233ee`)

Established the multi-platform release pipelines (GitHub Actions and Azure DevOps), added license files, fixed Windows pipeline Rust installation via the official rustup installer, ran `cargo fmt --all`, and cleared all clippy warnings across the workspace.

---
