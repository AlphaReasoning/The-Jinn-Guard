# Step 2: Mandatory Mediation Sandbox

Step 2 adds a locked agent runtime for development validation. The agent gets no
useful direct capability except access to the Jinn Guard Unix socket mounted by
the runtime compose profile.

```text
Sandboxed Agent
  -> only useful capability: /run/jinnguard/jinnguard.sock
  -> Jinn Guard Broker
  -> shell / filesystem / network / MCP / external tools
```

The important runtime policy change is that a proposed dangerous action is no
longer merely advisory. With `runtime_policy.require_brokered_execution: true`,
any proposal that contains `proposed_action` but does not set `execute: true` is
rejected with:

```text
SIGNAL: DENY_RUNTIME_POLICY
```

That closes the old pattern where an agent could ask for a verdict and then run
the action locally.

## Runtime Policy

`policy.step2.yaml` and the compatibility alias `policy.runtime.yaml` introduce:

```yaml
runtime_policy:
  deny_root_peers: true
  allowed_peer_uids:
    - 10001
  require_brokered_execution: true
  require_sandbox_namespace: false
```

The daemon checks kernel-observed Unix socket peer credentials before it returns
`ALLOW` or `CONSTRAIN`:

- UID `0` can be denied.
- Client UIDs can be allowlisted.
- Dangerous `proposed_action` requests can be forced onto the broker execution path.
- Optional PID/NET namespace separation can be required on hosts where `/proc`
  can observe peer namespaces reliably.

`--socket-mode` is opt-in. The runtime compose profile sets it to `0770` so the
locked agent can connect through the shared runtime socket volume.

## Locked Agent Container

`Dockerfile.agent` builds a minimal Python agent image with:

- non-root UID/GID `10001:1000`;
- no compiler toolchain;
- no shell binary at `/bin/sh`, `/bin/dash`, or `/bin/bash`;
- no curl/wget/nc helper binaries;
- code mounted read-only from `/workspace` at runtime.

`docker-compose.runtime.yml` runs:

- `jinnguard-broker`: broker container with the Rust dev image and the runtime policy.
- `locked-agent`: a capability-deprived probe container.

The locked agent uses:

- `network_mode: "none"`;
- `read_only: true`;
- `cap_drop: [ALL]`;
- `security_opt: [no-new-privileges:true, seccomp=./sandbox/agent-seccomp.json]`;
- `tmpfs` on `/tmp` with `noexec,nosuid,nodev`;
- a shared Unix-socket volume mounted at `/run/jinnguard`.

The `/run/jinnguard` path here is a container runtime volume path, not a change
to host systemd production behavior.

## Smoke Test

Run:

```bash
make runtime-smoke
```

The probe verifies:

1. locked-agent runtime attestation;
2. direct network egress is blocked;
3. direct sensitive file write is blocked;
4. direct shell is blocked;
5. verdict-only `proposed_action` is denied with `DENY_RUNTIME_POLICY`;
6. broker-owned shell execution is allowed and executed;
7. broker-owned file write is allowed and executed.

Useful commands:

```bash
make runtime-build
make runtime-smoke
make runtime-agent-probe
make runtime-agent-shell
make runtime-logs
make runtime-down
```

## Remaining Hardening

This step creates a real OS/container boundary for the demo path, but production
should still add:

- broker-owned secrets so agents never hold raw API credentials;
- MCP/API adapters that are reachable only from the broker network namespace;
- CI that runs the Docker bypass probes on a real Linux Docker host;
- production socket ownership using a dedicated Unix group;
- stricter AppArmor/SELinux profiles where the deployment target supports them;
- workload identities stronger than the shared dev HMAC.
