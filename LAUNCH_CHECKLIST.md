# Launch Checklist

Hygiene pass before the first distribution push to a security-literate audience
(r/netsec, HN, AFWERX/DIU-adjacent). The repo's intellectual-honesty framing
(validation-status section, `THREAT_MODEL.md`, "what it does NOT claim") is the
core asset — everything here aligns the rest of the repo up to that bar.

## Automated pass (branch `chore/launch-hygiene`)

- [x] **A — Kill self-assigned CVE identifiers.** Renamed project-assigned
      `CVE-2026-001/002/003` to internal advisory IDs `JG-ADV-2026-001/002/003`
      (numeric mapping preserved) across all documentation, with a one-line
      disclaimer at first use in `README.md` and `THREAT_MODEL.md`
      ("`JG-ADV-*` are internal, self-identified advisory IDs, not CVE records
      issued by a CNA"). Docs only — code/script comments deliberately left
      untouched (see flag in the PR summary).
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
