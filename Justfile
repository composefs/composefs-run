# Justfile for composefs-examples
# Run `just --list` to see available targets.
# --------------------------------------------------------------------

# Path to cfsctl binary (override with CFSCTL env var or `just cfsctl=/path/to/cfsctl`)
cfsctl := env("CFSCTL", "cfsctl")

# Build all crates
build:
    cargo build --workspace

# Build in release mode
build-release:
    cargo build --workspace --release

# Run unit tests only (no container image needed)
test-unit:
    cargo test --lib --bin cfsrun

# Run integration tests (pulls test image on first run, requires cfsctl)
test-integration: build
    CFSCTL={{cfsctl}} cargo test --test integration

# Run all tests
test: test-unit test-integration

# Run clippy lints
clippy:
    cargo clippy --workspace -- -D warnings

# Run rustfmt check
fmt-check:
    cargo fmt --all -- --check

# Format code
fmt:
    cargo fmt --all

# Run all checks (clippy + fmt + unit tests)
check: clippy fmt-check test-unit

# Run all checks including integration tests
check-all: clippy fmt-check test

# Clean build artifacts
clean:
    cargo clean
