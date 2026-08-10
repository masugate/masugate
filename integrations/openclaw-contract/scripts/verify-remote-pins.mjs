import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const contract = JSON.parse(
  await readFile(resolve(root, "contract/openclaw-v2026.7.1.json"), "utf8"),
);

const RETRY_ATTEMPTS = 4;

async function response(url, init = {}) {
  let failure;
  for (let attempt = 1; attempt <= RETRY_ATTEMPTS; attempt += 1) {
    let retryable = true;
    try {
      const result = await fetch(url, {
        ...init,
        signal: AbortSignal.timeout(120_000),
      });
      if (result.ok) return result;
      failure = new Error(`${url} returned ${result.status}`);
      retryable = result.status === 429 || result.status >= 500;
      if (!retryable) throw failure;
    } catch (error) {
      failure = error;
      if (!retryable || attempt === RETRY_ATTEMPTS) throw error;
    }
    if (attempt < RETRY_ATTEMPTS) {
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 500 * attempt));
    }
  }
  throw failure ?? new Error(`${url} request failed`);
}

async function bytes(url, init = {}) {
  return Buffer.from(await (await response(url, init)).arrayBuffer());
}

function digest(algorithm, value, encoding = "hex") {
  return createHash(algorithm).update(value).digest(encoding);
}

const releaseResponse = await response(
  `https://api.github.com/repos/openclaw/openclaw/releases/tags/${contract.release.tag}`,
  { headers: { Accept: "application/vnd.github+json", "User-Agent": "masugate-pin-oracle" } },
);
const release = await releaseResponse.json();
assert.equal(release.tag_name, contract.release.tag);
assert.equal(release.target_commitish, contract.release.commit);
assert.equal(release.published_at, contract.release.publishedAt);
assert.equal(release.html_url, contract.release.url);

const version = contract.npm.version;
const manifestName = `openclaw-${version}-release-manifest.json`;
const checksumName = `${manifestName}.sha256`;
const manifestAsset = release.assets.find((asset) => asset.name === manifestName);
const checksumAsset = release.assets.find((asset) => asset.name === checksumName);
assert.ok(manifestAsset, `release is missing ${manifestName}`);
assert.ok(checksumAsset, `release is missing ${checksumName}`);
assert.equal(manifestAsset.digest, `sha256:${contract.release.releaseManifestSha256}`);
assert.equal(
  checksumAsset.digest,
  `sha256:${contract.release.releaseManifestChecksumFileSha256}`,
);

const manifestBytes = await bytes(manifestAsset.browser_download_url);
const checksumBytes = await bytes(checksumAsset.browser_download_url);
assert.equal(digest("sha256", manifestBytes), contract.release.releaseManifestSha256);
assert.equal(digest("sha256", checksumBytes), contract.release.releaseManifestChecksumFileSha256);
const checksumLine = checksumBytes.toString("utf8").trim().split(/\s+/u);
assert.equal(checksumLine[0], contract.release.releaseManifestSha256);
assert.equal(checksumLine.at(-1)?.replace(/^\*/u, ""), manifestName);
const releaseManifest = JSON.parse(manifestBytes.toString("utf8"));
assert.equal(releaseManifest.targetRef, contract.release.commit);
assert.equal(releaseManifest.targetSha, contract.release.commit);

const npmTarball = await bytes(contract.npm.tarball);
assert.equal(digest("sha1", npmTarball), contract.npm.shasum);
assert.equal(`sha512-${digest("sha512", npmTarball, "base64")}`, contract.npm.integrity);

const nodeArchive = await bytes(contract.node.linuxX64Archive);
assert.equal(digest("sha256", nodeArchive), contract.node.linuxX64Sha256);
const nodeFilename = new URL(contract.node.linuxX64Archive).pathname.split("/").at(-1);
const nodeChecksums = await (
  await response(`https://nodejs.org/dist/v${contract.node.version}/SHASUMS256.txt`)
).text();
assert.match(
  nodeChecksums,
  new RegExp(`^${contract.node.linuxX64Sha256}  ${nodeFilename}$`, "mu"),
);

const registry = "https://ghcr.io/v2/openclaw/openclaw";
const tokenResponse = await response(
  "https://ghcr.io/token?service=ghcr.io&scope=repository:openclaw/openclaw:pull",
);
const { token } = await tokenResponse.json();
assert.equal(typeof token, "string");
const registryHeaders = {
  Authorization: `Bearer ${token}`,
  Accept:
    "application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json",
};
const indexResponse = await response(
  `${registry}/manifests/${encodeURIComponent(version)}`,
  { headers: registryHeaders },
);
assert.equal(indexResponse.headers.get("docker-content-digest"), contract.container.indexDigest);
const index = await indexResponse.json();
const platformDigest = (architecture) =>
  index.manifests.find(
    (entry) => entry.platform?.os === "linux" && entry.platform?.architecture === architecture,
  )?.digest;
assert.equal(platformDigest("amd64"), contract.container.linuxAmd64ManifestDigest);
assert.equal(platformDigest("arm64"), contract.container.linuxArm64ManifestDigest);

const manifestResponse = await response(
  `${registry}/manifests/${contract.container.linuxAmd64ManifestDigest}`,
  {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept:
        "application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json",
    },
  },
);
assert.equal(
  manifestResponse.headers.get("docker-content-digest"),
  contract.container.linuxAmd64ManifestDigest,
);
const imageManifest = await manifestResponse.json();
assert.equal(imageManifest.config.digest, contract.container.linuxAmd64ConfigDigest);
const configResponse = await response(`${registry}/blobs/${imageManifest.config.digest}`, {
  headers: { Authorization: `Bearer ${token}` },
});
const imageConfig = await configResponse.json();
const labels = imageConfig.config?.Labels ?? {};
assert.equal(labels["org.opencontainers.image.revision"], contract.container.sourceRevisionLabel);
assert.equal(labels["org.opencontainers.image.licenses"], contract.container.licenseLabel);
assert.ok(
  imageConfig.config?.Env?.includes(`NODE_VERSION=${contract.container.nodeVersion}`),
  "pinned image config must declare the pinned Node version",
);

console.log(
  `verified remote OpenClaw release, npm tarball, OCI image, and Node ${contract.node.version}`,
);
