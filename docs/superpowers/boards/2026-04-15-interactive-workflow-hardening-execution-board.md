# Interactive Workflow Hardening Execution Board

**Date:** 2026-04-15  
**Status:** Complete  
**Current Shape:** Interactive CLI workflow memory, replay/history, workspace discovery, persisted breadcrumb state  
**Source Inputs:** overall code review, security review, and test coverage review conducted on 2026-04-15

## Objective

Resolve the current correctness, security, and coverage findings in the interactive workflow layer without regressing the new quick menu, breadcrumb memory, replay features, or external validation surfaces.

## Findings In Scope

- `Convert` replay does not persist the originally selected format and can replay the wrong operation.
- Persisted workflow state stores sensitive operational metadata in cleartext without explicit permission hardening.
- Replay paths drop profile metadata for profile-aware jobs.
- Workspace artifact detection misclassifies PEM-suffixed key/CSR files as certificates.
- Workspace scanning follows symlinked directories and can surface filenames outside the intended root.
- Preview and validation-plan output render raw paths into shell-like snippets without safe escaping.
- `NewConfig` replay is not backward-compatible with older saved jobs that predate `replay_data`.
- Coverage is still thin around persistence round-trips and the replay/state-machine edge cases behind the findings above.

## Resolution Board

| ID | Finding | Resolution | Owner | Verification | Status |
|---|---|---|---|---|---|
| IWH-01 | `Convert` replay can change behavior on clone/repeat | Persist explicit replay format in job metadata and replay from stored format, not output suffix; add regression coverage | Main / Planck | `cargo test -p ssl-toolbox --bin ssl-toolbox` | Done |
| IWH-02 | Persisted state is written in cleartext with weak/default file permissions | Harden state-file creation/write permissions and preserve backward-compatible loading; add persistence tests | Main / Herschel | `cargo test -p ssl-toolbox --bin ssl-toolbox` | Done |
| IWH-03 | Replay drops profile metadata for profile-aware jobs | Preserve `job.profile` in replay builders and assert it in regression tests | Main / Planck | `cargo test -p ssl-toolbox --bin ssl-toolbox` | Done |
| IWH-04 | PEM-suffixed keys/CSRs are misclassified as certs | Refine artifact detection for compound PEM filenames and add regression tests | Main / Erdos | `cargo test -p ssl-toolbox --bin ssl-toolbox` | Done |
| IWH-05 | Workspace scan follows symlinked directories outside the root | Refuse recursive descent into symlinked directories and add scan coverage | Main / Erdos | `cargo test -p ssl-toolbox --bin ssl-toolbox` | Done |
| IWH-06 | Preview/validation shell snippets are unsafe to copy with hostile paths | Shell-escape command snippets and sanitize displayed path rendering where needed; add tests | Main / Erdos | `cargo test -p ssl-toolbox --bin ssl-toolbox` | Done |
| IWH-07 | `NewConfig` replay fails for older saved jobs without `replay_data` | Add backward-compatible replay fallback and regression coverage for legacy job state | Main / Planck | `cargo test -p ssl-toolbox --bin ssl-toolbox` | Done |
| IWH-08 | Persistence and replay edge cases are under-tested | Add tests for state round-trip and the replay regressions above, then rerun full workspace verification | Main | `cargo test --workspace` | Done |

## Decomposition

### Replay Correctness

- Persist replay-only metadata for format-sensitive jobs.
- Preserve profile metadata when replay jobs are rebuilt.
- Make `NewConfig` replay tolerate older history entries.
- Add focused regression tests in `crates/ssl-toolbox/src/main.rs`.

### Persistence Hardening

- Ensure `~/.ssl-toolbox/state.json` is created and rewritten with restrictive permissions where the platform supports it.
- Preserve existing state-file compatibility and avoid breaking older data.
- Add round-trip tests in `crates/ssl-toolbox/src/settings.rs`.

### Workflow Discovery And Rendering

- Fix compound PEM artifact detection.
- Stop recursive scan from traversing symlinked directories.
- Make shell-like validation snippets safe to copy/paste.
- Add regression tests in `crates/ssl-toolbox/src/workflow.rs`.

## Verification Plan

Commands to run after integration:

```text
cargo fmt --all
cargo test -p ssl-toolbox --bin ssl-toolbox
cargo test --workspace
```

Latest result in this checkout:

```text
cargo fmt --all                              passed
cargo test -p ssl-toolbox --bin ssl-toolbox passed
cargo test --workspace                      passed
```

## Completion Log

| Date | Entry | Status |
|---|---|---|
| 2026-04-15 | Findings decomposed into replay, persistence, and workflow-hardening workstreams | Done |
| 2026-04-15 | Three fix workers dispatched with disjoint file ownership | Done |
| 2026-04-15 | Replay correctness fixes integrated and regression-tested | Done |
| 2026-04-15 | Persistence hardening and legacy-state round-trip coverage added | Done |
| 2026-04-15 | Workflow scan/rendering hardening integrated and regression-tested | Done |
| 2026-04-15 | Full workspace verification rerun successfully in the current checkout | Done |

## Closeout

The findings scoped into this board are resolved in the current checkout and verified with both focused CLI tests and the full workspace test suite. Remaining interactive-flow coverage gaps outside these specific findings can be tracked separately if you want a follow-on hardening pass.
