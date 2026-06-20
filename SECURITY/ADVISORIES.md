# Jinn Guard — Security Advisories

This file is the **canonical registry** for Jinn Guard advisory identifiers.

> **`JG-ADV-*` are internal, self-identified advisory IDs, not CVE records issued
> by a CNA.** They track issues the project found in its own white-box audits and
> validation runs. Where another document references an advisory ID, this table is
> the source of truth for its meaning, scope, and status.

| ID | Title | Component | Disclosed | Status | Fix commit |
|---|---|---|---|---|---|
| JG-ADV-2026-001 | execve allowlist bypass via interpreter chains | `bprm_check_security` / user-space exec policy | 2026-06-08 | Mitigated | `3abbba3` |
| JG-ADV-2026-002 | filesystem policy bypass via relative paths | `inode_create` / `inode_unlink` (dentry path resolution) | 2026-06-08 | Fixed | `3676af7` |
| JG-ADV-2026-003 | agent impersonation via UID spoofing | identity / authentication model | 2026-06-08 | Mitigated | — (design: HMAC-SHA256 `agent_id` auth) |
| JG-ADV-2026-004 | fail-open in socket-LSM enforcement (two root causes) | `socket_connect` / `socket_sendmsg` | 2026-06-14 | Fixed | `6430ba9`, `b678455` |

## Notes

- **JG-ADV-2026-001 — interpreter chains.** A governed agent allowed to run an
  interpreter (`/bin/bash`, `python`, …) can drive other tools through it.
  *Mitigated:* governed agents with an executable allowlist are denied known
  interpreters; per-binary limits remain only as strong as that allowlist. Full
  elimination (child-process attribution) is tracked in `THREAT_MODEL.md` §10.

- **JG-ADV-2026-002 — relative-path bypass.** The inode hooks originally sent only
  the basename to user space, defeating prefix checks like `/etc/`. *Fixed* by
  kernel-side full-path resolution (`jg_read_dentry_path`, bounded `d_parent`
  walk). Residual: sub-mount paths resolve relative to their mount root;
  root-filesystem paths (the security-critical cases) resolve absolutely.

- **JG-ADV-2026-003 — UID spoofing.** From the historical white-box audit
  (`red-team-report.md`), which described an aspirational mTLS identity model
  whose placeholder derived identity from the OS UID. *Mitigated:* the shipped
  system authenticates the OS user via `SO_PEERCRED` (unforgeable) **and** the
  application `agent_id` via HMAC-SHA256 — identity is not taken from a spoofable
  UID. Residual: a single shared HMAC key is not bound per-agent/UID, so a
  principal able to read the key can sign as any `agent_id`; strong multi-tenant
  isolation (per-agent secrets / `agent_id`↔UID binding) is tracked in
  `THREAT_MODEL.md` §7.8 and §10.

- **JG-ADV-2026-004 — socket-LSM fail-open.** Surfaced on AlmaLinux 9 / kernel
  5.14 (Run 04): `socket_connect` leaked a variable fraction of denied connects
  under load. Two independent root causes — a load-window race (hooks attached
  before policy maps were populated) and a `sock->type` read-width bug (a 2-byte
  kernel field read into a 4-byte local pulled padding that flipped a gate open).
  *Fixed* by populate-then-attach and by reading the correct field width;
  re-validated on the host that exposed it (0 fail-open, `BENCHMARKS-04.md` §2).

_Last updated: 2026-06-19._
