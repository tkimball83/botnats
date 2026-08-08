# Changes

Minimal, scoped diffs. Delete what is unused.

## Scope

- Fix demonstrated issues without speculative functionality.
- Keep changes within the requested scope.
- Avoid wire-format changes without a concrete requirement.
- Before 1.0, replace obsolete wire and storage formats in place; do not add legacy compatibility or
  migrations unless explicitly requested.

## Cleanup

- Delete pass-through wrappers, unused values, unused defaults, and speculative flexibility.
- Reuse existing owners and stdlib before adding abstractions or dependencies.

## Git

- Preserve unrelated worktree changes.
- Do not mention external repositories in commit messages.
