# Changes

Minimal, scoped diffs. Delete what is unused.

- Fix demonstrated issues, within the requested scope.
- Avoid wire-format changes without a concrete requirement. Before 1.0, replace obsolete wire and
  storage formats in place; add legacy compatibility or migrations only when asked.
- Delete pass-through wrappers, unused values and defaults, and speculative flexibility.
- Reuse existing owners and the stdlib before adding abstractions or dependencies.
- Rename identifiers that still describe replaced behavior.
- Preserve unrelated worktree changes. Do not mention external repositories in commit messages.
