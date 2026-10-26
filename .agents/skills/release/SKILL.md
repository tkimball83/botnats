---
name: release
description: Cut a versioned release branch and PR.
---

# release

1. Set `version` in `pyproject.toml` to `{{ version }}` and run `make test`.
2. Open the release PR:

   ```sh
   git checkout -b release/v{{ version }}
   git add pyproject.toml
   git commit -m "Release v{{ version }}"
   git push -u origin release/v{{ version }}
   gh pr create --title "Release v{{ version }}" --body "Release v{{ version }}"
   ```

3. Once CI passes, merge and publish the release; its tag publishes the matching image:

   ```sh
   gh pr merge {{ pr }} --merge
   gh release create v{{ version }} --title "v{{ version }}" --notes "{{ notes }}"
   ```

## Dependencies

- `virtualenv` skill
- `test` skill
