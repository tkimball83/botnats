---
name: new-module
description: Create a new Python source module.
---

# new-module

Start every source file with:

```python
# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""One-line module docstring."""
```

- IRC transport and protocol code goes in `irc/`, NATS code in `nats/`.
- Modules that coordinate owners through `Bot` (events, commands, channels) go at the package
  root.
- Add `tests/unit/test_{{ name }}.py`: `unittest.TestCase`, or `IsolatedAsyncioTestCase` for
  async code.

## Dependencies

- `virtualenv` skill
