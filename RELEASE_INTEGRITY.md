# Release integrity: provenance, signatures, and verification

Jinn Guard release artifacts are built, attested, and signed by the
[`release.yml`](.github/workflows/release.yml) workflow, which runs **only** on a
pushed version tag (`v*`). Each release publishes:

| Asset | What it is |
|---|---|
| `ts_cli` | the release binary |
| `jinnguard-sbom.cyclonedx.json` | CycloneDX SBOM of the full dependency graph |
| `rebuild-and-compare.txt` | reproducible-build verification report |
| `checksums.txt` | sha256 of the binary, SBOM, and rebuild report (the SLSA subjects) |
| `*.sig` / `*.pem` | cosign keyless detached signature + signing certificate per artifact |
| `*.intoto.jsonl` | SLSA v3 build provenance attestation |

The signing keys are **ephemeral** (Sigstore keyless / OIDC): there is no
long-lived private key to leak. Trust is anchored on the **build identity** — the
GitHub Actions workflow's OIDC identity — recorded in the signing certificate and
the provenance, and verified against the public Rekor transparency log.

## Verifying a download

### 1. Checksums
```sh
sha256sum -c checksums.txt
```

### 2. Signature (cosign, keyless)
Verify the binary was signed by *this* repo's release workflow:
```sh
cosign verify-blob \
  --certificate ts_cli.pem \
  --signature ts_cli.sig \
  --certificate-identity-regexp '^https://github.com/AlphaReasoning/The-Jinn-Guard/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ts_cli
```
The same command with the SBOM's `.pem`/`.sig` verifies the SBOM.
The rebuild report is signed the same way:
```sh
cosign verify-blob \
  --certificate rebuild-and-compare.txt.pem \
  --signature rebuild-and-compare.txt.sig \
  --certificate-identity-regexp '^https://github.com/AlphaReasoning/The-Jinn-Guard/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  rebuild-and-compare.txt
```

### 3. SLSA provenance
Using [`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier):
```sh
slsa-verifier verify-artifact ts_cli \
  --provenance-path *.intoto.jsonl \
  --source-uri github.com/AlphaReasoning/The-Jinn-Guard \
  --source-tag <the release tag>
```
This proves the binary was produced by the expected workflow from the expected
source at the expected tag — not substituted after the fact.

## Reproducible builds — verified scope

Release reproducibility is verified by
[`scripts/rebuild_and_compare_release.sh`](scripts/rebuild_and_compare_release.sh).
The script:

- archives the tagged commit into two clean source directories,
- builds `ts_cli` twice with `cargo build -p ts_cli --release --locked`,
- pins `SOURCE_DATE_EPOCH` to the tagged commit timestamp,
- disables incremental compilation,
- remaps source and Cargo-home paths out of the binary,
- strips symbols, and
- byte-compares the two resulting release binaries.

`rust-toolchain.toml` pins the release compiler to a concrete toolchain version.
`release.yml` publishes only the binary that passed the rebuild comparison, and
it includes the signed `rebuild-and-compare.txt` report in the release assets.
Normal PR/push CI also runs the same rebuild comparison so regressions are caught
before a release tag is cut.

To verify locally:

```sh
git fetch --tags
git checkout <the release tag>
scripts/rebuild_and_compare_release.sh \
  --ref <the release tag> \
  --output /tmp/ts_cli.rebuilt \
  --report /tmp/rebuild-and-compare.txt
sha256sum /tmp/ts_cli.rebuilt
```

The rebuilt binary's hash should match the `ts_cli` entry in `checksums.txt`.
This is a Linux x86_64, pinned-toolchain reproducibility claim for the release
binary. It is still separate from the SLSA provenance and Sigstore authenticity
checks above, which prove where the published artifact came from.

## What the supply-chain story covers now

- **Dependency policy** — `cargo deny check` (advisories / licenses / bans /
  sources) gates every push/PR via the `Supply chain` CI job (#46 Phase 1).
- **Bill of materials** — a CycloneDX SBOM is produced on every CI build and on
  every release.
- **Build provenance** — SLSA v3 attestation per release (this document).
- **Authenticity** — cosign keyless signatures per release artifact.
- **Reproducibility** — the release binary is rebuilt twice from clean archives
  and byte-compared before publication.
