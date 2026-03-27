FROM dhi.io/rust:1.92-alpine3.22-dev AS build

RUN apk add --no-cache openssl-dev pkgconfig file make git openssl-libs-static

WORKDIR /build

RUN --mount=type=bind,source=src,target=src \
    --mount=type=bind,source=Cargo.toml,target=Cargo.toml \
    --mount=type=bind,source=Cargo.lock,target=Cargo.lock \
    --mount=type=bind,source=build.rs,target=build.rs \
    --mount=type=cache,target=/build/target/ \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/usr/local/cargo/registry/ \
    cargo build --locked --release && \
    cp /build/target/release/ds_proxy /build/ds_proxy


FROM dhi.io/alpine-base:3.22 AS production

COPY --from=build --chown=nonroot:nonroot /build/ds_proxy /dsproxy/ds_proxy

EXPOSE 4444

ENTRYPOINT ["/dsproxy/ds_proxy"]