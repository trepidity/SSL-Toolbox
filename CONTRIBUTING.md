# Contributing to ssl-toolbox

## Issues

All features and bug reports must be tracked as GitHub Issues before any work begins. Issues are the authoritative record of intent — PRs without a corresponding issue will not be merged.

Issues must identify:
- What tests are missing or need updating
- What behavior the fix/feature should produce (testable acceptance criteria)
- Whether [ARCHITECTURE.md](ARCHITECTURE.md) needs updating — any feature or behavioral change that isn't already described in ARCHITECTURE.md **must** include an architecture update in the same PR. The architecture doc is the spec; code without a spec is untestable by definition.

## Test-Driven Development

All code changes follow strict TDD. The flow is one-directional:

```
ARCHITECTURE.md (defines behavior) → Tests (encode behavior) → Code (satisfies tests)
```

[ARCHITECTURE.md](ARCHITECTURE.md) is the authoritative technical schematic. **Tests are written to the architecture spec. Code is written to pass the tests. Never modify a test to make code pass.** If a test fails, either the code is wrong (fix the code) or the test was written incorrectly against the spec (fix the test to match the spec, not the code). The architecture spec is the source of truth.

If the architecture is wrong or incomplete, update ARCHITECTURE.md first, then update tests to match, then update code.

### TDD Red-Green-Refactor cycle

1. **Red** — write tests that describe the expected behavior per the spec/issue. Run them. They must fail. If they pass, either the behavior already exists or the test isn't testing what you think.
2. **Green** — write the minimum implementation code to make the tests pass. Do not change tests during this phase.
3. **Refactor** — clean up code while keeping tests green. Do not change test assertions.

### Rules

1. **Issues identify test gaps** — every issue must note what tests are missing or need updating.
2. **CI must pass** — the GitHub Actions workflow runs on every push and PR. PRs with failing checks will not be merged. The required gates are:
   - `cargo test --workspace`
   - `cargo clippy --workspace -- -D warnings`
   - `cargo fmt --all --check`
   - `cargo check -p ssl-toolbox --no-default-features` (sans-Sectigo build)
3. **No masked signals** — tests must use exact assertions, not weak upper-bound checks. Prefer `assert_eq!(result, Ok(expected))` over `assert!(result.is_ok())`. Do not assert `count > 0` when you know the exact count. Every test must fail if the behavior it guards breaks. Review tests for false-passing patterns before submitting.
4. **Spec is authoritative** — if there's a conflict between what the code does and what the spec says, the spec wins. Update code to match spec, not the other way around. If the spec is wrong, update the spec first, then the tests, then the code.

### Local pre-push

Enable the repo's pre-push hook so clippy and fmt run before every push:

```bash
git config core.hooksPath .githooks
```

The `.githooks/pre-push` hook runs `cargo fmt --all -- --check` followed by `cargo clippy --workspace -- -D warnings` and aborts the push on any failure.

Run tests locally: `cargo test --workspace`

## Pull Requests

All changes require a PR against `main`. Direct commits to `main` are not permitted.

**PR requirements:**
- Reference the issue in the PR description (`Closes #N` or `Ref #N`)
- Include a `CHANGELOG.md` entry under `[Unreleased]` — one entry per issue, referencing the issue number for full context
- If the PR introduces or changes behavior, [ARCHITECTURE.md](ARCHITECTURE.md) must be updated in the same PR. No feature merges without a matching spec update.
- All code review comments must be acknowledged and addressed before merge — no unresolved items at merge time
- CI must be green before merge
- **Feature-flag rule** — any PR touching `ssl-toolbox-ca-sectigo` or the `sectigo` feature must also pass `cargo check -p ssl-toolbox --no-default-features`. The sans-Sectigo build is a first-class target, not an afterthought.

## CHANGELOG Format

Each PR adds an entry under `## [Unreleased]` in `CHANGELOG.md`:

```markdown
### <type>: <short description> (`<commit-sha>`) — closes #N

One or two sentences describing what changed and why.
Reference [#N](https://github.com/trepidity/SSL-Toolbox/issues/N) for full context.
```

Types: `feat`, `fix`, `docs`, `chore`, `decision`.

`decision` entries are for architectural or policy decisions that have no direct code change — they document _why_ something is or isn't done and should be preserved long-term.
