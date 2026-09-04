// packages/policy/src/pure.ts
// The fs-free subset of the package's surface: everything in ./index.js except loadLayerFile
// (./load.js), which statically imports node:fs. Import "@auora/policy/pure" instead of
// "@auora/policy" where the consumer (e.g. a Cloudflare Worker) must not pull node:fs into its
// bundle; import loadLayerFile itself from a Node-hosted caller (the daemon) that can afford it.
export * from "./types.js";
export * from "./compile.js";
export * from "./guard.js";
export * from "./evaluate.js";
export * from "./explain.js";
export * from "./simulate.js";
export * from "./decision.js";
