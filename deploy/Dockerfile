# BWOC Gateway — long-running relay service.
# Build: docker build -f deploy/Dockerfile -t bwoc-gateway .
# Run:   docker run -p 8787:8787 -e BWOC_GATEWAY_ADDR=0.0.0.0:8787 bwoc-gateway
# Fronted by nginx-proxy (Cloudflare Flexible SSL) for wss:// in the bemind stack.

FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p gateway-server

FROM debian:bookworm-slim
RUN useradd -r -u 10001 gateway
COPY --from=build /src/target/release/bwoc-gateway /usr/local/bin/bwoc-gateway
USER gateway
ENV BWOC_GATEWAY_ADDR=0.0.0.0:8787
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/bwoc-gateway"]
