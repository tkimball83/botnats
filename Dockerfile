FROM python:3.14-alpine

WORKDIR /app
COPY . .
RUN python -m pip install --no-cache-dir .

USER 65534:65534
ENTRYPOINT ["botnats"]
