# Protected connector worker

The protected connector worker is a closed recovery process, not a
caller-facing execution service. It reads a deployment-mounted bootstrap,
recovers only provider-committed handoffs, and obtains its connector only from
the sealed registry/deployment identity inside that document. The invocation
cannot select a module, factory, destination, secret reference, or policy.

The reviewed deployment controls are:

- [`Dockerfile.release`](../connectors/worker/Dockerfile.release), which builds
  from the verified `masugate`, connector-SDK, and filesystem-connector wheels
  plus their locked wheelhouse; it never copies a source checkout.
- [`compose.fragment.yaml`](../connectors/worker/compose.fragment.yaml), which
  requires a locally built or loaded reviewed artifact through
  `MASUGATE_CONNECTOR_WORKER_IMAGE`, runs as UID 10001, has a read-only root,
  drops every Linux capability, enables no-new-privileges, and has only the
  internal connector network.
- [`bootstrap.example.json`](../connectors/worker/bootstrap.example.json), a
  closed, zero-handoff example. Replace its route, registry, store, and secret
  facts only with an assembled deployment's matching facts; it is not a
  runnable effect example and contains no secret.

## Local artifact and one-pass containment check

After the [one-time reviewer setup](artifact-evaluation.md#exact-one-time-setup),
assemble the worker from the same verified release used by the reference
demonstration. The output directory must be absent. This is a local Docker
operation: it uses a preflighted digest, `--pull=false`, `--network=none`, and
an empty Docker configuration; it neither publishes nor contacts a registry.

```sh
. /tmp/masugate-reviewer-setup/reviewer.env
cd "$MASUGATE_CANDIDATE_DIR"
test ! -e /tmp/masugate-connector-worker
export MASUGATE_CONTAINER_ARTIFACT_TMPDIR=/tmp
"$MASUGATE_REVIEWER_PYTHON" scripts/build-connector-worker-artifact.py \
  --release-dir "$MASUGATE_RELEASE_VERIFICATION_RELEASE_DIR" \
  --expected-source-revision "$MASUGATE_SOURCE_REVISION" \
  --expected-staging-realization-revision "$(git rev-parse HEAD)" \
  --docker "$MASUGATE_DOCKER_BIN" \
  --outdir /tmp/masugate-connector-worker
```

The command writes `connector-worker-artifact.json` and a `docker save`
archive. Before saving it runs the image's entrypoint as UID 10001 with no
network, read-only root, no capabilities, no-new-privileges, read-only
bootstrap/secret mounts, and disposable tmpfs state. The bundled bootstrap has
no handoffs, so the expected one-pass output is `{"recovered": 0, "scanned": 0}`.
Before saving, it loads the installed `masugate-connector-filesystem`
distribution through its sealed `filesystem` entry point and verifies the
`filesystem-v1` identity. It deliberately does not claim an effect from an
arbitrary Docker bind mount: this connector requires a deployment-provisioned,
dedicated ext4 mount. The builder also renders the Compose fragment with the
just-built local tag, then removes that transient tag after writing the archive.

Verify the retained archive in a fresh Docker configuration:

```sh
. /tmp/masugate-reviewer-setup/reviewer.env
cd "$MASUGATE_CANDIDATE_DIR"
export MASUGATE_CONTAINER_ARTIFACT_TMPDIR=/tmp
"$MASUGATE_REVIEWER_PYTHON" scripts/build-connector-worker-artifact.py \
  --release-dir "$MASUGATE_RELEASE_VERIFICATION_RELEASE_DIR" \
  --expected-source-revision "$MASUGATE_SOURCE_REVISION" \
  --expected-staging-realization-revision "$(git rev-parse HEAD)" \
  --docker "$MASUGATE_DOCKER_BIN" \
  --verify \
  --artifact-dir /tmp/masugate-connector-worker
```

An operational deployment must supply durable state, secret, and bootstrap
volumes whose contents exactly match the sealed deployment. This candidate does
not provide a production deployment or authorize an external connector effect.
Remove only the dedicated `/tmp/masugate-connector-worker` directory after
review.

Version: `0.1.0` (research preview). Next: [Reproduction](reproduction.md).
