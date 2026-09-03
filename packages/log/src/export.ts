// packages/log/src/export.ts
import type { EventStore } from "./store.js";

export function exportRunJsonl(store: EventStore, runId: string): string {
  const lines: string[] = [];
  for (const event of store.list(runId)) lines.push(JSON.stringify({ record: "event", ...event }));
  for (const body of store.loadCheckpoints(runId)) lines.push(JSON.stringify({ record: "checkpoint", ...(JSON.parse(body) as object) }));
  return lines.join("\n") + "\n";
}
