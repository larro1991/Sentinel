# ── Builder stage ──────────────────────────────────────────────────────────────
FROM rust:1.90-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY src/ ./src/

RUN cargo build --release && \
    strip target/release/sentinel

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -s /usr/sbin/nologin sentinel

COPY --from=builder /build/target/release/sentinel /usr/local/bin/sentinel

RUN mkdir -p /config /results && chown sentinel:sentinel /results

# Honeypot ports + dashboard.
EXPOSE 22 25 80 443 2121 2323 3306 3389 5353/udp 5432 8080 9090

VOLUME ["/config", "/results"]

USER sentinel

ENTRYPOINT ["sentinel"]
CMD ["watch", "-c", "/config/engagement.yaml"]
