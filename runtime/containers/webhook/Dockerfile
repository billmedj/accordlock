# syntax=docker/dockerfile:1.7

# Both images are mandatory build inputs. Supply immutable digest references,
# for example `registry/repository@sha256:<64 hex>`. There are deliberately no
# mutable defaults.
ARG ACCORDLOCK_RUST_BUILDER_IMAGE
ARG ACCORDLOCK_RUNTIME_IMAGE

FROM ${ACCORDLOCK_RUST_BUILDER_IMAGE} AS build
ARG ACCORDLOCK_RUST_BUILDER_IMAGE
ARG ACCORDLOCK_RUNTIME_IMAGE
WORKDIR /workspace
RUN set -eu; \
    for reference in "$ACCORDLOCK_RUST_BUILDER_IMAGE" "$ACCORDLOCK_RUNTIME_IMAGE"; do \
      case "$reference" in *@sha256:*) ;; *) exit 64 ;; esac; \
      digest="${reference##*@sha256:}"; \
      [ "${#digest}" -eq 64 ] || exit 64; \
      case "$digest" in *[!0-9a-f]*) exit 64 ;; esac; \
      name="${reference%@sha256:*}"; \
      [ -n "$name" ] || exit 64; \
      case "${name##*/}" in *:*) exit 64 ;; esac; \
    done
COPY . .
RUN cargo build --frozen --release -p accordlock-webhook --bin accordlock-webhookd

FROM ${ACCORDLOCK_RUNTIME_IMAGE}
COPY --from=build /workspace/target/release/accordlock-webhookd /usr/local/bin/accordlock-webhookd
USER 65532:65532
EXPOSE 9443
ENTRYPOINT ["/usr/local/bin/accordlock-webhookd"]
