# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

FROM python:3.14.10-alpine

WORKDIR /app
COPY pyproject.toml .
RUN python -c "import tomllib; \
    print('\n'.join(tomllib.load(open('pyproject.toml', 'rb'))['project']['dependencies']))" \
    | python -m pip install --no-cache-dir -r /dev/stdin
RUN --mount=type=bind,target=/src,rw python -m pip install --no-cache-dir --no-deps /src

USER 65534:65534
ENTRYPOINT ["botnats"]
