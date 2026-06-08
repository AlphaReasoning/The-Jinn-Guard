# Jinn Guard Rust sandbox
#
# Development/test image, not a production runtime image. It provides Cargo,
# native Z3, Python, SQLite/OpenSSL headers, Clang/LLVM, and optional eBPF
# build tools so the repository can be built without depending on the host.
FROM rust:1-bookworm

ARG USERNAME=jinnguard
ARG USER_UID=1000
ARG USER_GID=${USER_UID}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        bpftool \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        curl \
        git \
        iproute2 \
        jq \
        keyutils \
        lld \
        llvm \
        make \
        netcat-openbsd \
        pkg-config \
        python3 \
        python3-pip \
        python3-venv \
        sqlite3 \
        strace \
        sudo \
        unzip \
        zstd \
        libbpf-dev \
        libclang-dev \
        libssl-dev \
        libsqlite3-dev \
        libz3-dev \
        linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add rustfmt clippy

RUN groupadd --gid "${USER_GID}" "${USERNAME}" \
    && useradd --uid "${USER_UID}" --gid "${USER_GID}" --create-home --shell /bin/bash "${USERNAME}" \
    && echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/${USERNAME}" \
    && chmod 0440 "/etc/sudoers.d/${USERNAME}" \
    && mkdir -p /workspace \
    && chown "${USERNAME}:${USERNAME}" /workspace

WORKDIR /workspace

ENV CARGO_TARGET_DIR=/workspace/target \
    JINN_GUARD_SECRET=dev-secret-not-for-production \
    JINN_GUARD_SOCKET=/tmp/jinnguard-runtime/jinnguard.sock \
    JINNGUARD_SOCKET=/tmp/jinnguard-runtime/jinnguard.sock \
    RUST_BACKTRACE=1

USER ${USERNAME}

CMD ["bash"]
