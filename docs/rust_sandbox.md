# Rust Sandbox / Dev Environment

Jinn Guard ships with a project-owned Rust sandbox for development, CI-style builds, and Step 1 capability-broker testing. It is intended for repeatable local development, not production runtime enforcement.

## What The Sandbox Includes

- Rust/Cargo from the official `rust:1-bookworm` base image
- `rustfmt` and `clippy`
- native Z3 library and headers through `libz3-dev`
- OpenSSL and SQLite development headers
- Python 3 for the Python SDK and demos
- Clang/LLVM/LLD and basic eBPF build tools
- Docker Compose workflow
- VS Code Dev Container workflow
- shared Cargo and target caches
- shared runtime socket volume for daemon/demo testing across containers

## Fast Path

From the repository root:

```bash
make docker-build
make dev-shell
```

Inside the sandbox shell:

```bash
make build
make check
```

Equivalent direct commands:

```bash
docker compose build jinnguard-sandbox
docker compose run --rm jinnguard-sandbox bash
./scripts/sandbox_build.sh
./scripts/sandbox_test.sh
```

## Step 1 Broker Smoke Test

The quickest validation path starts the daemon and runs the Step 1 capability-broker demo in one sandbox container:

```bash
make docker-smoke
```

That runs:

```bash
./scripts/sandbox_smoke.sh
```

The smoke test builds the Rust workspace, starts `ts_cli` with local development paths, waits for the Unix socket, runs `examples/step1_capability_broker_demo.py`, and then cleans up the daemon.

## Two-Terminal Daemon/Demo Flow

The Compose setup mounts a shared runtime volume at `/tmp/jinnguard-runtime`, so separate sandbox containers can communicate over the same Unix socket.

Terminal 1:

```bash
docker compose run --rm jinnguard-sandbox ./scripts/sandbox_run_daemon.sh
```

Terminal 2:

```bash
docker compose run --rm jinnguard-sandbox ./scripts/sandbox_demo_step1.sh
```

Both use these development defaults inside Docker Compose:

```bash
JINN_GUARD_SECRET=dev-secret-not-for-production
JINN_GUARD_SOCKET=/tmp/jinnguard-runtime/jinnguard.sock
JINN_GUARD_MCP_PORT=4850
```

For local non-Docker runs, the default socket is `/tmp/jinnguard.sock` unless `JINN_GUARD_SOCKET` or `JINNGUARD_SOCKET` is set.
The sandbox MCP gateway defaults to port `4850` to avoid colliding with production/default port `4750`.
If the port is busy, override it before starting the sandbox daemon:

```bash
export JINN_GUARD_MCP_PORT=4860
./scripts/sandbox_run_daemon.sh
```

For production, replace the development secret and use the systemd runtime socket path `/run/jinnguard/jinnguard.sock`.

## Local Machine Without Docker

If Rust and the native dependencies are already installed locally:

```bash
make build
make check
make smoke
```

## VS Code Dev Container

Open the repository in VS Code and choose **Reopen in Container**. The `.devcontainer/devcontainer.json` file uses the same Docker Compose service and installs Rust Analyzer, TOML support, LLDB, and Python tooling.

## Enterprise / eBPF Note

The default sandbox is for normal Rust development and Step 1 broker testing. The optional kernel telemetry / eBPF path still requires a privileged Linux host with BPF LSM support. Do not expect the kernel enforcement layer to work inside an ordinary unprivileged container.

## Step 2 Runtime Sandbox

For mandatory mediation validation, use the locked runtime compose profile:

```bash
make runtime-smoke
```

That flow is documented in [step2_mandatory_mediation_sandbox.md](step2_mandatory_mediation_sandbox.md).
