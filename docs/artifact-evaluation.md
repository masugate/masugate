# Artifact evaluation

**Audience:** artifact reviewers. Start with [Concepts](concepts.md), then
[Reproduction](reproduction.md). **Supported boundary:** the `0.1.1`
research-preview release and its checked-in descriptor, not a production deployment.

## Review checklist

1. Confirm the reference descriptor at
   [`release/reference-release.json`](../release/reference-release.json) names
   `masugate-openclaw-reference/0.1.1`, Linux/amd64, and CPython 3.12.
2. After the exact setup below, run the local descriptor integrity check:

   ```sh
   . /tmp/masugate-reviewer-setup/reviewer.env
   cd "$MASUGATE_CANDIDATE_DIR"
   "$MASUGATE_REVIEWER_PYTHON" scripts/build-reference-release.py --verify-only
   ```

3. Inspect the closed protocol schemas in
   [`protocol/schemas/`](../protocol/schemas/) and the corresponding examples
   in [`protocol/examples/`](../protocol/examples/).
4. Follow the code path in the [governed action walkthrough](governed-action-walkthrough.md).
5. Treat a failed command as a failed gate. Do not replace it with a claim of
   success, and do not use an optional live-service result as proof of the
   required local tier.

## Platform and resource profile

The descriptor’s supported target is Linux/amd64 with CPython 3.12. The
validated reviewer toolchain is CPython `3.12.3`, Git `2.43.0`, Node.js
`24.16.0`, npm `11.13.0`, uv `0.11.26`, Docker Engine `29.6.1`, and Docker
Compose `5.3.0`. Node, npm, and uv are exact setup requirements; the Python
patch, Git, Docker, and Compose versions name the tested profile. The setup
script rejects a non-Linux/amd64 Docker target, a Python version outside 3.12,
or missing Compose support.

Allow 15 minutes and 8 GiB of free disk for a cold setup. The retained setup
directory is expected to stay below 500 MiB after build-only caches are removed;
Docker’s six pinned bases and temporary first-party demo images can use up to
6 GiB. The one-time setup typically completes within 10 minutes on a broadband
connection. The measured credential-free demonstration is separately limited
to five minutes and usually retains less than 25 MiB of JSON and staged output.

## Exact one-time setup

Start in a clean Git checkout of this release. The following is the complete
setup command; `/tmp/masugate-reviewer-setup` must not already exist:

```sh
test ! -e /tmp/masugate-reviewer-setup
python3 scripts/prepare-reference-demo.py \
  --outdir /tmp/masugate-reviewer-setup
```

Success prints
`MasuGate reviewer inputs: /tmp/masugate-reviewer-setup/reviewer.env`.
The script creates a second clean local clone, installs the exact hash-bound
Python environment, builds the release, prepares and then revalidates the
OpenClaw-contract npm cache offline, and writes the exact environment values
used by the README. It also pulls and verifies these six descriptor identities:

| Setup action | Exact image |
|---|---|
| `docker image pull` | `node:24.16.0-alpine@sha256:21f403ab171f2dc89bad4dd69d7721bfd15f084ccb46cdd225f31f2bc59b5c9a` |
| `docker image pull` | `docker:27.5.1-cli-alpine3.21@sha256:851f91d241214e7c6db86513b270d58776379aacc5eb9c4a87e5b47115e3065c` |
| `docker image pull` | `python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7` |
| `docker image pull` | `nginx:1.27.5-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10` |
| `docker image pull` | `postgres:17.5-alpine@sha256:6567bca8d7bc8c82c5922425a0baee57be8402df92bae5eacad5f01ae9544daa` |
| `docker image pull` | `alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d` |

The setup uses anonymous access only to `pypi.org`, `files.pythonhosted.org`,
`registry.npmjs.org`, and the registries serving those six public images.
Python files must match
[`reference-demo-build.requirements.lock`](../release/requirements/reference-demo-build.requirements.lock),
npm tarballs must match
[`integrations/openclaw-contract/package-lock.json`](../integrations/openclaw-contract/package-lock.json),
runtime wheels must match
[`pylock.masugate-platform.toml`](../release/requirements/pylock.masugate-platform.toml),
and every image must match its descriptor digest. The script removes credential-
shaped environment variables and uses empty home, npm, Docker, and XDG
configuration. It inherits only `PATH`, `LANG`, `LC_ALL`, and `TZ`; caller
proxies, alternate indexes, registry overrides, netrc paths, and authentication
helpers do not enter retrieval subprocesses. It records that allowlist along
with tools, hashes, paths, image IDs, elapsed setup time, and retained bytes in
`/tmp/masugate-reviewer-setup/setup-manifest.json`.

After setup, disconnect or block network access and provide no credentials.
Run the exact [README demonstration](../README.md#five-minute-local-demonstration).
Its environment file resolves to:

| Input | Exact location or value |
|---|---|
| Clean runnable release | `/tmp/masugate-reviewer-setup/candidate` |
| Python interpreter | `/tmp/masugate-reviewer-setup/venv/bin/python` |
| Verified release | `/tmp/masugate-reviewer-setup/release` |
| Lock-bound npm cache | `/tmp/masugate-reviewer-setup/demo-npm-cache` |
| Immutable source revision | `1373f5507c1680c60a7700d8a6c26a8b4d3fb025` |
| Source timestamp | `1785365155` |

The full reference demonstration uses containers and a disposable state
directory. It can create containers, networks, images, and JSON evidence under
the selected output directory. Use a disposable output directory and remove it
after inspection. Do not point a demo at a production database, filesystem
mount, account, or credential.

## Known limits

The [claims and limitations](claims-and-limitations.md) page identifies the
named evidence gate for each recorded claim. Some gates require a clean
artifact, local container topology, or a reviewed exact environment. Treat the
named gate as the requirement; neither a checked-in path nor a narrower local
test is a substitute. A gate is passed only when its required command succeeds
against the required artifact and its result is recorded.

To remove the retained reviewer setup after all evidence has been inspected,
leave its candidate directory and remove only the documented disposable root:

```sh
cd /tmp
rm -r -- /tmp/masugate-reviewer-setup
```

The six digest-pinned base images are shared Docker cache inputs and are not
removed automatically. Remove them only under the local Docker administrator’s
normal image-retention policy.

Version: `0.1.1` (research preview). Next: [Reproduction](reproduction.md).
