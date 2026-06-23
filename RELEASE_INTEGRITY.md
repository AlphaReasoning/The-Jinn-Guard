# Release integrity: provenance, signatures, and verification

Jinn Guard release artifacts are built, attested, and signed by the
[`release.yml`](.github/workflows/release.yml) workflow, which runs **only** on a
pushed version tag (`v*`). Each release publishes:

| Asset | What it is |
|---|---|
| `ts_cli` | the release binary |
| `jinnguard-sbom.cyclonedx.json` | CycloneDX SBOM of the full dependency graph |
| `checksums.txt` | sha256 of the binary and SBOM (the SLSA subjects) |
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

## Reproducible builds — honest scope

`release.yml` pins `SOURCE_DATE_EPOCH` to the tagged commit's timestamp and builds
with `--locked` (the committed `Cargo.lock` fixes every dependency version). This
removes the most common sources of timestamp/dependency nondeterminism, **but the
build is not yet independently verified to be bit-for-bit reproducible.** A full
reproducible-build guarantee (pinned toolchain image, stripped build paths, a
documented `rebuild-and-compare` procedure) is tracked as the remaining open
sub-item of #46 and is **not claimed here**. Until it is verified and documented,
trust in an artifact rests on the **provenance + signature** above, not on
independent rebuild.

## What the supply-chain story covers now

- **Dependency policy** — `cargo deny check` (advisories / licenses / bans /
  sources) gates every push/PR via the `Supply chain` CI job (#46 Phase 1).
- **Bill of materials** — a CycloneDX SBOM is produced on every CI build and on
  every release.
- **Build provenance** — SLSA v3 attestation per release (this document).
- **Authenticity** — cosign keyless signatures per release artifact.
- **Open** — independently-verified reproducible builds.
