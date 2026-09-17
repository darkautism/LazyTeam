FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p lazyteam-server

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 lazyteam \
    && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin lazyteam \
    && mkdir -p /data \
    && chown -R lazyteam:lazyteam /data
COPY --from=builder /src/target/release/lazyteam-server /usr/local/bin/lazyteam-server
WORKDIR /app
ENV LAZYTEAM_DATABASE_URL=sqlite:///data/lazyteam.db?mode=rwc
USER lazyteam:lazyteam
EXPOSE 8787
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["curl", "-fsS", "http://127.0.0.1:8787/health"]
ENTRYPOINT ["lazyteam-server"]
