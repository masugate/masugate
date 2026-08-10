# Release engineering controls

**Audience:** release reviewers. **Supported boundary:** the `0.1.0`
research-preview release only. The source repository is public and its bounded
source-control workflow is active. This document describes reproducible local
verification controls; it does not authorize package or container publication,
a registry account, or a hosted artifact release.

The checked-in release descriptor defines one Linux/amd64 CPython 3.12 reference
set. [`compatibility-matrix.json`](../release/compatibility-matrix.json)
enumerates its fourteen Python wheels/sdists and four npm tarballs. It is derived
from [`reference-release.json`](../release/reference-release.json), so a stale
or widened package set is a failure rather than a compatibility promise.

Run the static release-control check before preparing a release:

```sh
python scripts/verify-release-controls.py
python scripts/verify-documentation.py
python scripts/build-reference-release.py --verify-only
```

The verifier requires exact commit pins for every GitHub Action, valid PEP 621
metadata for every Python package, an enabled read-only source-control workflow,
a manual-only disabled compatibility workflow, and a disabled OIDC release
design. The latter records PyPI, npm, and container-attestation roles without
configuring a trusted publisher or using a long-lived publishing secret.
The source-control workflow retrieves only the checked-in hash-locked verifier
environment and builds the in-tree connector SDK without resolving dependencies.

[`release-control-policy.json`](../release/release-control-policy.json) records
the future two-person control: two distinct approvers must be required for a
release environment, workflow or owner-role changes, namespace or domain
transfers, and release deletion. Actual identities and hosting controls remain
outside the source tree and configured separately before an external release.

Build output belongs below an empty, explicitly chosen directory. The builder
writes package archives, deployment inputs, checksums, a CycloneDX SBOM, and
provenance there; it never publishes them. Use the clean reviewer setup and
release gate described in [Artifact evaluation](artifact-evaluation.md) for the
complete artifact-backed evidence tier.

An isolated rebuild may pass `--offline-wheelhouse /path/to/locked-wheels`.
The builder copies only files whose names and SHA-256 digests match the checked-in
Python lock; a missing or mismatched wheel fails the build without a network
fallback.

The deployment inputs include a path-neutral npm clean-consumer lock template.
[`verify-npm-clean-consumer.py`](../scripts/verify-npm-clean-consumer.py) makes
an empty private consumer directory, substitutes only the selected release
tarball directory, performs `npm ci --offline` against the reviewed cache, and
imports each npm package's public entry point. It rejects any package version
outside the source lock or any local path embedded in the template. The template
contains exactly eight `file:__MASUGATE_RELEASE_NPM__/…` references: one direct
dependency and one resolved package record for each MasuGate npm tarball.
Before installation the verifier replaces that marker with the selected
release's `npm/` directory, then requires every resulting reference to name
the corresponding built tarball. A relative build directory, a temporary path,
or any other local dependency is rejected.

## Container archive reproduction

The reference container images are assembled locally from the same verified
release directory and the reviewed offline inputs. The builder uses
`--pull=false` and `--network=none`, records every first-party image ID and
archive digest, and writes a `docker save` archive plus a JSON manifest below
an explicit output directory. Base-image digests remain declared in
`reference-release.json`; no image is pushed or published.

After the [one-time reviewer setup](artifact-evaluation.md#exact-one-time-setup),
run the following from a clean release checkout. The output directory must be absent.

```sh
. /tmp/masugate-reviewer-setup/reviewer.env
cd "$MASUGATE_CANDIDATE_DIR"
test ! -e /tmp/masugate-reference-container
export MASUGATE_CONTAINER_ARTIFACT_TMPDIR=/tmp
"$MASUGATE_REVIEWER_PYTHON" scripts/build-reference-container-artifact.py \
  --release-dir "$MASUGATE_RELEASE_VERIFICATION_RELEASE_DIR" \
  --expected-source-revision "$MASUGATE_SOURCE_REVISION" \
  --expected-staging-realization-revision "$(git rev-parse HEAD)" \
  --docker "$MASUGATE_DOCKER_BIN" \
  --offline-npm-cache "$MASUGATE_OFFLINE_NPM_CACHE" \
  --outdir /tmp/masugate-reference-container
```

Success prints `reference container artifact written:` followed by
`/tmp/masugate-reference-container/container-artifact.json`. The command builds
four first-party images without a network, validates the saved archive, removes
the transient local tags, and retains only the named archive and manifest below
the output directory. To verify that retained archive in a fresh local Docker
context, run this separate command (the verifier intentionally accepts neither
an npm cache nor an output directory):

```sh
. /tmp/masugate-reviewer-setup/reviewer.env
cd "$MASUGATE_CANDIDATE_DIR"
export MASUGATE_CONTAINER_ARTIFACT_TMPDIR=/tmp
"$MASUGATE_REVIEWER_PYTHON" scripts/build-reference-container-artifact.py \
  --release-dir "$MASUGATE_RELEASE_VERIFICATION_RELEASE_DIR" \
  --expected-source-revision "$MASUGATE_SOURCE_REVISION" \
  --expected-staging-realization-revision "$(git rev-parse HEAD)" \
  --docker "$MASUGATE_DOCKER_BIN" \
  --verify \
  --artifact-dir /tmp/masugate-reference-container
```

Success then prints `reference container artifact verified`. The verifier loads
the archive, checks each image identity, and removes the loaded tags. After
inspection, remove only `/tmp/masugate-reference-container`.

The companion [protected connector worker](protected-worker.md) control builds
and reloads its own single-image archive from the same verified release. Its
one-pass lifecycle uses the image entrypoint and closed bootstrap under the
checked-in Compose containment profile; it does not use a source checkout.

## Review boundary

The local gate records paths, archive hashes, logs, and timings in its explicit
output directory. Those records support review only. They do not authorize
package or container publication, registry access, a trusted publisher, or a
hosted artifact release.

Version: `0.1.0` (research preview). Next: [Protected connector worker](protected-worker.md).
