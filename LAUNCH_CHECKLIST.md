# Launch Checklist

Hygiene pass before the first distribution push to a security-literate audience
(r/netsec, HN, AFWERX/DIU-adjacent). The repo's intellectual-honesty framing
(validation-status section, `THREAT_MODEL.md`, "what it does NOT claim") is the
core asset — everything here aligns the rest of the repo up to that bar.

## Automated pass (branch `chore/launch-hygiene`)

- [x] **A — Kill self-assigned CVE identifiers.** Renamed project-assigned CVE
      identifiers to internal `JG-ADV-*` advisory IDs across docs and (in the
      follow-up pass) code comments + script output strings. Rename record:
      - `CVE-2026-001` -> `JG-ADV-2026-001` (execve interpreter-chain bypass)
      - `CVE-2026-002` -> `JG-ADV-2026-002` (filesystem relative-path bypass)
      - `CVE-2026-003` -> `JG-ADV-2026-003` (agent impersonation / UID spoofing)
      - `CVE-2026-003` -> `JG-ADV-2026-004` (socket-LSM fail-open — renumbered to
        resolve the duplicate-`003` collision; the newer finding takes the new
        number)

      A one-line disclaimer was added at first use in `README.md` and
      `THREAT_MODEL.md` ("`JG-ADV-*` are internal, self-identified advisory IDs,
      not CVE records issued by a CNA"). Canonical registry:
      [`SECURITY/ADVISORIES.md`](SECURITY/ADVISORIES.md).
- [x] **B — Fix the register collision.** Retitled the README headline from
      "Enterprise Semantic Firewall" to "Kernel-level enforcement firewall for
      autonomous AI agents (research prototype)" to match the validation-status
      section. The Fleet & Enterprise feature-tier section (feature-gated, off by
      default) is legitimate and left as-is.
- [x] **C — Repo metadata.** About/description + topics command prepared (run
      manually — `gh` not available in the working environment; exact command in
      the PR summary).
- [x] **D — Fix the language bar.** Marked `bpf/**` `linguist-vendored` in
      `.gitattributes` so the language bar reads Rust-primary. GitHub re-indexes
      on the next push.

## Manual (human, not agent)

- [ ] **MANUAL** — Re-record demo: screen-recorder window must never overlay
      terminal content (currently covers the open and the closing thesis card).
- [ ] **MANUAL** — Post demo as a **native LinkedIn video** (uploaded, not a
      link). Put the repo URL in the **first comment**, not the post body.
- [ ] **MANUAL** — Warm DM to a named contact for a repost into the
      AFWERX/DIU-adjacent network.
