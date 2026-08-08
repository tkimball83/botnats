---
name: release
description: Cut a versioned release branch and PR.
---

# release

Bump the version in `pyproject.toml` and open a release PR.

1. Update `version` in `pyproject.toml` to `{{ version }}`.
2. Run `make test` before cutting the release.
3. Create branch `release/v{{ version }}`.
4. Commit, push, and open a PR to `main`.
5. Wait for CI to pass before merging.
6. Merge the PR, then create the GitHub release.

```sh
git checkout -b release/v{{ version }}
git add pyproject.toml
git commit -m "Release v{{ version }}"
git push -u origin release/v{{ version }}
gh pr create --title "Release v{{ version }}" \
  --body "Release v{{ version }}"
```

After CI passes:

```sh
gh pr merge {{ pr }} --merge
gh release create v{{ version }} \
  --title "v{{ version }}" --notes "{{ notes }}"
```

## Dependencies

- `virtualenv` skill
- `test` skill
