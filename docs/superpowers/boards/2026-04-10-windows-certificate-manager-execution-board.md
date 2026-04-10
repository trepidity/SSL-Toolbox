# Windows Certificate Manager Execution Board

**Date:** 2026-04-10  
**Status:** In Progress  
**Current Shape:** Windows CLI + ratatui browser backed by PowerShell certificate-store commands  
**Source Spec:** `docs/superpowers/specs/2026-04-10-windows-certificate-manager-design.md`

## Objective

Move the Windows certificate manager from the earlier cliclack/CLI v1 into a more mature interactive Windows toolset while keeping the board honest about what is actually implemented in this repo versus what still remains.

## Delivered Across Both Passes

- Added the `ssl-toolbox-win-certstore` workspace crate.
- Added shared PKCS#7 format detection to `ssl-toolbox-core`.
- Added Windows `certstore` CLI commands for store enumeration and certificate operations.
- Replaced the old cliclack browse flow with a Windows-only ratatui certificate manager entrypoint.
- Added resumable `--certmgr-*` launch plumbing for Windows certificate manager resume/elevation flows.
- Added private-key inspection metadata retrieval and UI surfaces.
- Added Windows-only live certificate-store integration tests for CI/release runners.
- Added backend/location scaffolding for `current-service`, named service stores, and alternate-user store contexts.
- Added physical-store discovery APIs and a ratatui physical-store browse flow.
- Kept non-Windows builds and tests clean.

## Current Task Board

| ID | Task | Owner | Verification | Status |
|---|---|---|---|---|
| WCM-IMP-01 | Add workspace/core support for PKCS#7 detection | Main | `ssl-toolbox-core` unit tests pass | Done |
| WCM-IMP-02 | Create the Windows certstore crate with a usable API surface | Main | New crate exists and compiles on non-Windows via stubs | Done |
| WCM-IMP-03 | Implement Windows store list/show/import/export/delete operations | Main | Library functions exist and are wired to PowerShell-backed Windows operations | Done |
| WCM-IMP-04 | Add Windows CLI commands to `ssl-toolbox` | Main | `certstore` command family exists on Windows | Done |
| WCM-IMP-05 | Replace the cliclack browse entry with a ratatui Windows browser | Main | `certstore browse` and menu item now launch the ratatui browser | Done |
| WCM-IMP-06 | Add resumable elevation launch plumbing | Main | Hidden `--certmgr-*` args added and TUI can relaunch elevated with resume context | Done |
| WCM-IMP-07 | Add private-key inspection metadata/UI | Main | CLI detail output and TUI detail view can inspect key metadata | Done |
| WCM-IMP-08 | Add Windows live-host integration tests beyond build-only validation | Main | Windows workflow now enables a live store lifecycle test | Done |
| WCM-IMP-09 | Implement full Win32 exact-handle backend | Main | No PowerShell/provider-path dependency remains for item identity and operations | Open |
| WCM-IMP-10 | Add physical store browsing | Main | User can browse logical and physical stores | In Progress |
| WCM-IMP-11 | Add service/user/impersonation store support | Main | Service stores and alternate-user stores are reachable in product flows | In Progress |
| WCM-IMP-12 | Final review, board update, and gap closure | Main | Board reflects actual state and remaining work is explicit | Done |

## Files Changed In This Phase

- `Cargo.toml`
- `Cargo.lock`
- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `crates/ssl-toolbox/Cargo.toml`
- `crates/ssl-toolbox/src/main.rs`
- `crates/ssl-toolbox/src/win_certmgr.rs`
- `crates/ssl-toolbox-win-certstore/src/lib.rs`
- `crates/ssl-toolbox-win-certstore/src/platform.rs`
- `crates/ssl-toolbox-win-certstore/tests/windows_live.rs`

## Validation

Commands executed in this environment:

```text
cargo fmt
cargo test
```

Latest native result:

```text
workspace status: passed
ssl-toolbox-core tests: 8 passed
ssl-toolbox-win-certstore tests: 5 passed
failures: 0
```

Additional validation attempted:

```text
cargo check --target x86_64-pc-windows-msvc
```

That Windows-target check still failed on this macOS host because the vendored OpenSSL Windows build path requires a Windows-compatible Perl/toolchain setup that is not present here. This remains a host-environment limitation. Real Windows validation is now delegated to GitHub Actions, where the Windows jobs run the workspace tests with `SSL_TOOLBOX_ENABLE_WINDOWS_LIVE_TESTS=1`.

## Gaps Reviewed

| Gap | Outcome | Status |
|---|---|---|
| No ratatui implementation existed | Added a Windows-only ratatui browser and menu/CLI wiring | Closed |
| No private-key inspection flow existed | Added metadata inspection API plus TUI/CLI usage | Closed |
| No UAC resume wiring existed | Added hidden resume args and relaunch plumbing | Closed |
| Windows CI only proved build/test, not live store behavior | Added a live Windows lifecycle test gated on the Windows runner env var | Closed |
| Full Win32 exact-handle identity is still missing | Current backend still relies on PowerShell/provider-path item resolution | Open |
| Physical store browsing was missing | Backend discovery and a TUI physical-store flow now exist, but Windows runtime behavior is not yet proven here | In Progress |
| Service/user/impersonation store support was missing | Backend context model and UI selection flows now exist, but full Windows validation and import-path parity are not complete | In Progress |

## Remaining Backlog

These items remain open after this pass:

| Backlog ID | Item |
|---|---|
| NEXT-01 | Replace the PowerShell/provider-path backend with the planned Win32 exact-handle architecture |
| NEXT-02 | Validate and harden physical-store browsing on a Windows host, including duplicate-sensitive operations |
| NEXT-03 | Finish service store and alternate-user/impersonation support, including import-path parity and Windows validation |
| NEXT-04 | Broaden the ratatui browser with richer filtering, sorting, pagination, and modal flows |

## Completion Log

| Date | Entry | Status |
|---|---|---|
| 2026-04-10 | Shared PKCS#7 support implemented in `ssl-toolbox-core` | Done |
| 2026-04-10 | `ssl-toolbox-win-certstore` crate added and wired into the workspace | Done |
| 2026-04-10 | Windows CLI commands added | Done |
| 2026-04-10 | ratatui browser replaced the old browse flow | Done |
| 2026-04-10 | Private-key inspection metadata and UI added | Done |
| 2026-04-10 | Resume/elevation plumbing added | Done |
| 2026-04-10 | Windows live-store CI tests added | Done |
| 2026-04-10 | Backend/store context model expanded for current-service, service, user-store, and physical-store flows | Done |
| 2026-04-10 | ratatui browser wired to qualified location and physical-store APIs | Done |
| 2026-04-10 | Final native validation and review completed | Done |

## Closeout

This board is intentionally not marked complete. The mature Windows toolset is further along than the shipped v1, but the remaining backend/store-coverage items are still open and explicitly tracked instead of being implied complete.
