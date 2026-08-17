FROM rust:1.97-trixie AS rust-build

ARG DOCKER_BUILD=1

WORKDIR /aqueduct

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked

FROM debian:trixie-slim

WORKDIR /aqueduct

COPY --from=rust-build /aqueduct/target/release/aqueduct-client .

CMD ["./aqueduct-client"]