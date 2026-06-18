# R-VPN Server Dockerfile
# Multi-stage build for minimal image size

FROM rust:1.75-bookworm as builder

WORKDIR /app

# Copy workspace configuration
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/

# Build release binary
RUN cargo build --release -p rvpn-server

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    iptables \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /sbin/nologin -M rvpn

# Copy binary from builder
COPY --from=builder /app/target/release/rvpn-server /usr/local/bin/

# Create config directory
RUN mkdir -p /etc/rvpn && chown rvpn:rvpn /etc/rvpn

# Expose ports
EXPOSE 443/tcp 8080/tcp

# Switch to non-root user
USER rvpn

# Default command
CMD ["rvpn-server", "--config", "/etc/rvpn/server.toml"]
