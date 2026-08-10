/** Stage physical runtime packages so npm can include them as bundled dependencies.
 *
 * npm workspaces hoist local packages as symlinks.  `npm pack` intentionally
 * omits those links, so `bundledDependencies` alone would produce a tarball
 * which OpenClaw later tries to satisfy from a registry.  Copy only the
 * published runtime surfaces into this ignored staging directory immediately
 * before packing; `postpack` removes it again.
 */
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workspaceRoot = resolve(packageRoot, "../..");
const stagedNodeModules = resolve(packageRoot, "node_modules");

function packageName(source) {
  return JSON.parse(readFileSync(resolve(source, "package.json"), "utf8")).name;
}

function copyPublishedWorkspacePackage(name, source) {
  if (packageName(source) !== name) {
    throw new Error(`runtime source ${source} does not identify ${name}`);
  }
  const destination = resolve(stagedNodeModules, name);
  mkdirSync(dirname(destination), { recursive: true });
  for (const entry of ["package.json", "README.md", "LICENSE", "dist"]) {
    const from = resolve(source, entry);
    if (existsSync(from)) {
      cpSync(from, resolve(destination, entry), { recursive: true });
    }
  }
}

function copyRegistryPackage(name, source) {
  if (packageName(source) !== name) {
    throw new Error(`runtime source ${source} does not identify ${name}`);
  }
  const destination = resolve(stagedNodeModules, name);
  mkdirSync(dirname(destination), { recursive: true });
  cpSync(source, destination, {
    filter: (from) => basename(from) !== "node_modules",
    recursive: true,
  });
}

rmSync(stagedNodeModules, { force: true, recursive: true });
copyPublishedWorkspacePackage("@masugate/client", resolve(workspaceRoot, "clients/typescript"));
copyPublishedWorkspacePackage("@masugate/adapter-core", resolve(workspaceRoot, "adapters/typescript"));
copyRegistryPackage("typebox", resolve(workspaceRoot, "node_modules/typebox"));
