# Changelog

All notable changes to ssl-toolbox are documented here.

---

## [Unreleased]

### perf: CA operations reuse their access token, and time out

Every CA call re-authenticated before doing its work, so each operation cost two
round trips. A token is now reused for four minutes, which matters most to
search: filling in dates for a 25-row page drops from 50 requests to 26.
`ca test-connection` still authenticates fresh, since proving the credentials
work now is the whole point of it.

CA requests also gained a 30-second timeout. They previously had none, against
ARCHITECTURE.md §12.10 — a stalled connection hung the desktop app with no way
out but force-quitting it.

### feat: find a certificate the CA has already issued

New **Certificate Authority → Find certificate** screen and `ssl-toolbox ca search`,
matching on common name, subject alternative name, serial number, and status.
Each row shows status, requested date, and expiry — with a badge for how long is
left — so the list is answerable at a glance. The CA's list endpoint returns
identifiers only, so those columns cost one extra request per row; they run in
bounded concurrent batches against a cached token, and `ca search --no-dates`
skips them. Opening a row fetches the rest: profile, term, requester, comments.

The ID a result carries is the same one Collect takes, so finding a certificate
and downloading it is one path instead of two. `ssl-toolbox ca show --id N` prints
the full record.

Search hits the classic `/api/ssl/v1` endpoint — the same API generation as
enrolment and collection — and has been exercised against a live tenant.

### change: the Profiles screen is gone

Loading profiles is a button on Submit CSR, where a profile is actually chosen.
`ssl-toolbox ca list-profiles` is unchanged.

### fix: certificate collection requested the wrong artifact

`--format chain` asked Sectigo for `x509CO`, which is *certificate only* — every
chain download was silently a bare leaf. `--format pkcs7` sent `pkcs7`, which is
not a value Sectigo accepts at all. Both are corrected against Sectigo's
published `valid_formats` list, and the mapping is now pinned by a test.

Collection also returns bytes rather than text, so the binary PKCS#7 format is
no longer corrupted by a lossy UTF-8 round trip on the way to disk.

### feat: all seven CA retrieve formats

The collect screen and `ca collect --format` now offer what the CA console
offers: certificate only, certificate with issuer after, certificate with chain,
PKCS#7, PKCS#7 PEM, intermediates/root, and root/intermediates. The default
changed from leaf-only to `chain`, which is what a web server usually needs.
`--format pem` still resolves to certificate-only for anyone scripting it.

### feat: submitted request IDs are remembered

A request ID is the only handle on an in-flight order and arrives when nobody is
writing things down. Submissions are now recorded in the workspace — subject,
description, profile, and timestamp — and the desktop Collect screen offers them
as a dropdown. `ssl-toolbox ca requests` prints the same list, so an ID submitted
from the app is reachable from the terminal and vice versa.

`ca submit --out` is now optional, since the ID no longer depends on a file.

### feat: profile and term pickers on Submit CSR

Submitting requires a certificate profile, which previously meant typing a
product code from memory. The submit screen now has a **Load profiles** button, a
profile dropdown, and a term dropdown whose options come from the selected
profile — the CA rejects any other term, so it is no longer possible to type one.

### feat: paste a certificate or CSR instead of picking a file

Inspect Certificate and Inspect CSR accept pasted PEM, or the bare base64 body
with the `-----BEGIN-----` lines stripped off, which is how these usually arrive
in a ticket. Inspect CSR also gained a Copy button; what it copies is normalised
PEM, so it works even when the request was supplied as DER or as bare base64.

### feat: every CLI report can be saved

`view-cert`, `view-csr`, `view-pfx`, `view-config`, `identify`, `ca list-profiles`,
`ca requests`, and `ca settings` take `--out FILE`, matching the `verify-*`
commands. The file gets exactly what the terminal got.

### feat: CA credentials move from `.env` into an encrypted vault

CA client credentials no longer have to live in a `.env` file. They are stored
in `~/.ssl-toolbox/credentials.vault`, sealed with scrypt + AES-256-GCM under a
passphrase you choose, and both front-ends read the same vault.

This fixes a defect rather than adding a convenience: the desktop app never
loaded `.env`, and an app launched from Finder or the Start menu inherits no
shell environment — so the CA screens could not authenticate at all outside a
terminal-launched build.

- **Desktop** — new **Certificate Authority → Settings** screen for the endpoint
  configuration, the stored credentials, and a Test connection check. It shows
  which configuration layer each value is coming from, so a saved value that is
  being shadowed by a project file or an environment variable is visible rather
  than mysterious.
- **CLI** — `ca settings`, `ca configure`, `ca login`, `ca logout`, and
  `ca test-connection`. No `--client-secret` flag exists: a secret passed as an
  argument lands in shell history and `ps` output, so it is prompted for.
- **Environment variables still override the vault.** CI jobs, containers, and
  jump hosts that export `SCM_CLIENT_ID` / `SCM_CLIENT_SECRET` are unaffected.
  Setting only one of the pair is now an error instead of a silent fallthrough
  to the vault, which would have authenticated as a different account.
- `ssl-toolbox-ca-sectigo` no longer reads the environment; it is handed an
  identity by `ssl-toolbox-ops`, which owns credential resolution.

The vault passphrase is the only key — there is no recovery if it is lost.

---

## v2.1.4 — 2026-08-13

### feat: copy a newly generated CSR

The CSR success result now shows its PEM text and a one-click Copy CSR action
that writes the complete request to the native system clipboard.

---

## v2.1.3 — 2026-08-13

### fix: reliably publish release artifacts

Release checksums now discover the CLI archives and Windows installers even
when GitHub Actions stores downloaded artifacts in subdirectories.

---

## v2.1.2 — 2026-08-13

### fix: publish Windows desktop installers

The release workflow now builds the Tauri desktop application on Windows and
attaches both MSI and NSIS installers to every tagged release. Their checksums
are included alongside the CLI archives.

---

## v2.1.1 — 2026-08-13

### feat: verify SQL Server certificates

Added `verify-sql-server` for checking the certificate SQL Server presents on
TCP 1433 (or a supplied port). The check supports direct TLS for TDS 8.0 strict
mode and TDS PRELOGIN negotiation for traditional SQL Server endpoints, then
stops before authentication or SQL execution. The same capability is available
in the desktop Verify navigation, persists its endpoint history, and can export
the presented chain as PEM files.

### fix: desktop app could not be built from a clean checkout

`tauri.conf.json` set `frontendDist` to `../ui/dist`, the path that is correct
under the conventional `src-tauri/` layout. This crate keeps `tauri.conf.json`
at its root alongside `ui/`, so the path resolved to `crates/ui/dist` and
`cargo tauri build` failed with "Unable to find your web assets" after the Vite
build had already succeeded. Neither CI workflow builds the GUI, so nothing
caught it.

---

## v2.1.0 — 2026-08-12

### feat: headless ops layer, Tauri GUI, and OpenSSL config editing

The cliclack TUI is replaced by a desktop front-end, and both front-ends now run on one shared engine. The new `ssl-toolbox-ops` crate takes one `OpRequest` and returns one `OpResult`; it never prompts, prints, or touches a terminal, so CLI/GUI parity holds by construction rather than by convention. `audit`, `settings`, and `workflow` moved there from the CLI, and `main.rs` shrank from ~4,500 to ~1,100 lines — a bare `ssl-toolbox` now prints help.

The new `ssl-toolbox-gui` crate is Tauri v2 + React + TypeScript. Secrets live only in component-local state and are cleared in a `finally` on every submit; devtools are compiled into debug builds only, so a release binary cannot inspect a webview that has held a passphrase.

### feat: view and edit OpenSSL configs

New `LoadConfig` / `SaveConfig` ops, exposed as `view-config` / `save-config` on the CLI and Create → Edit config in the GUI. The file text is the source of truth: loads return it byte-for-byte, saves write it byte-for-byte, and neither routes through the generator — regenerating from a parse would silently destroy comments, `req_extensions`, and custom OID sections. Saves copy the previous contents to `<path>.bak` before writing.

The config reader implements the real `config(5)` grammar: a default section above the first `[section]`; `$var` / `${var}` / `$sec::var` / `${sec::var}` / `$ENV::var` expansion; double quotes preserving whitespace and single quotes literal; `#` comments only outside quotes; backslash escapes and line continuation; `.include` resolved against the file's own directory with a depth cap; `.pragma` consumed and reported as unapplied. DN attributes are read in either spelling (`CN` / `commonName`) and with OpenSSL's `N.` ordering prefix.

### feat: typed RFC 5280 SAN model

SANs are now `SanName { kind, value }` instead of delimited strings, covering the seven `GeneralName` choices OpenSSL config syntax can express. Numbering is per type, `dirName` emits the section it references, and write-time validation rejects a malformed IP, RID, or `otherName` before anything is written. The GUI enters SANs as one row per name with an explicit type.

### fix: load private keys without prompting or draining stdin

`PKey::private_key_from_pem` installs OpenSSL's default passphrase callback, which prompts on the terminal and consumes stdin — verified empirically. Three call sites reached it (`key_csr::generate_csr` and two in `pfx`). All now use a non-prompting helper with an explicit zero-length callback, preserving the "try unencrypted first" behavior while failing cleanly on an encrypted key.

---

## v2.0.5 — 2026-07-16

### fix: reconstruct TLS peer certificate chains in path order

HTTPS, LDAPS, and SMTP verification no longer trust the wire order of the peer certificate stack. Chains are rebuilt leaf → intermediate → root using a three-tier issuer match: signature verification plus subject/issuer DN, then `X509_check_issued`, then DN equality alone. Same-name impostor CAs lose to the signature-verified issuer.

When the server's presented order differs from the reconstructed path, `TlsCheckResult.chain_sent_out_of_order` is set and the report shows a warning. Display and `--export-certs` use the reordered path so exported PEMs are usable by strict clients.

---

## v2.0.4 — 2026-05-26

### feat: export endpoint certificate chains

Added `--export-certs DIR` to HTTPS and LDAPS verification so returned certificate chains can be saved as one PEM file per certificate. Interactive HTTPS/LDAPS checks can also export the same PEM files, preserving the displayed chain order.

---

## v2.0.3 — 2026-04-21

### fix: preserve certificate chain order and reuse chain rendering

`view-cert` now preserves PEM bundle order exactly as provided and infers leaf/intermediate/root labels from chain direction instead of reordering certificates. TLS verification output reuses the same certificate-chain renderer, so file inspection and live HTTPS/LDAPS checks present chain details consistently.

### fix: align Sectigo SCM integration with current admin API

Updated the Sectigo integration defaults to use `https://admin.enterprise.sectigo.com`, switched SSL profile lookup to the documented `orgId` query parameter, and fail fast when `SECTIGO_ORG_ID` is missing instead of surfacing a misleading remote 401.

---

## v2.0.2 — 2026-04-21

### feat: save verify reports to file

Added `--out` support to `verify-https`, `verify-ldaps`, and `verify-smtp` so the rendered verification report can be written directly to disk in the same format shown in the terminal.

### fix: align manual chain validation with system trust store

Adjusted post-handshake certificate validation to ignore server-sent self-signed roots in the untrusted stack and initialize OpenSSL trust-store discovery via `openssl-probe`. This resolves false chain verification failures seen in HTTPS and LDAPS while matching `openssl s_client` behavior.

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
