# overstep — matrix-driven authorization testing for HTTP APIs.
#
# A small image that installs the package and exposes the CLI as the entrypoint,
# so a pipeline can run:
#   docker run --rm -v "$PWD:/work" -w /work ghcr.io/kabiri-labs/overstep \
#       run matrix.yaml --out out
FROM python:3.12-slim

LABEL org.opencontainers.image.title="overstep" \
      org.opencontainers.image.description="Matrix-driven authorization testing for HTTP APIs (BOLA/BFLA/privilege escalation/auth drift)." \
      org.opencontainers.image.source="https://github.com/kabiri-labs/overstep" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /src

# Install dependencies first for better layer caching, then the package itself.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# Reports and matrices live in the mounted workspace, not the image.
WORKDIR /work

ENTRYPOINT ["overstep"]
CMD ["--help"]
