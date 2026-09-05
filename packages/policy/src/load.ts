// packages/policy/src/load.ts
// The package's one filesystem-touching entry point, kept out of compile.ts so that a Worker can
// import evaluate (and the rest of the pure surface) without pulling node:fs into its bundle; see
// packages/policy/src/pure.ts and the "./pure" subpath in packages/policy/package.json.
import { readFileSync } from "node:fs";
import { compileLayer, parseBundle } from "./compile.js";
import type { CompiledLayer } from "./types.js";

export function loadLayerFile(path: string, name: string): CompiledLayer {
  return compileLayer(parseBundle(readFileSync(path, "utf8")), name);
}
