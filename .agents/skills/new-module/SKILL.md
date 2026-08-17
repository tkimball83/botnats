---
name: new-module
description: Create a new Python source module.
---

# new-module

Every source file starts with:

```python
# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""One-line module docstring."""
```

Place IRC and NATS modules in their existing subpackages. Place other modules at
the package root unless a genuine domain boundary requires a new subpackage.
Export a public name from `__init__.py` only when package callers need it.

Add `tests/unit/test_{{ name }}.py` with `unittest.TestCase`. Prefer fakes for
focused behavior and standard-library mocks at external boundaries.

## Dependencies

- `virtualenv` skill
