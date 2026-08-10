import { copyFileSync } from "node:fs";

copyFileSync(
  new URL("../src/adapter-core-conformance.json", import.meta.url),
  new URL("../dist/adapter-core-conformance.json", import.meta.url),
);
