FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p lazyteam-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git openssh-client && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/lazyteam-server /usr/local/bin/lazyteam-server
RUN mkdir -p /data
WORKDIR /app
ENV LAZYTEAM_DATABASE_URL=sqlite:///data/lazyteam.db?mode=rwc
EXPOSE 8787
VOLUME ["/data"]
ENTRYPOINT ["lazyteam-server"]
