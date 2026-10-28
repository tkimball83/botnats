# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

FROM python:3.14.10-alpine

RUN --mount=type=bind,source=pyproject.toml,target=/tmp/pyproject.toml \
    python -c "import tomllib; \
    print('\n'.join(tomllib.load(open('/tmp/pyproject.toml', 'rb'))['project']['dependencies']))" \
    > /tmp/requirements.txt \
    && python -m pip install --no-cache-dir -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt
RUN --mount=type=bind,target=/src,rw python -m pip install --no-cache-dir --no-deps /src

USER 65534:65534
ENTRYPOINT ["botnats"]
