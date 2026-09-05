# Auora AI

A stateful action firewall for AI coding agents.

Auora starts each agent run (Claude Code, Codex CLI, or any command) inside an operating-system sandbox, turns every tool call the agent proposes into a typed action, evaluates a deterministic policy (allow, throttle, require approval, deny, terminate), forces name resolution and network traffic through its own resolver and proxy, injects scoped credentials so agent processes never hold secrets, runs the JavaScript agents write inside V8 isolates, and keeps a signed, hash-chained log of every decision. A dashboard you deploy to your own Cloudflare free account shows runs, decisions and behavior signals, and relays approvals to your phone, which signs them with its own key.

## Status

The first of seven sub-projects, the decision core (the wire contracts, the two-tier policy engine, the behavior signals and the signed log), is implemented as libraries with a mutation-checked test suite. Nothing runs as a product yet: the launcher, daemon, hook shims, sandbox adapter, resolver, proxy, isolate runner and dashboard are later sub-projects.

The design specification is the source of truth: [docs/superpowers/specs/2026-09-02-auora-ai-design.md](docs/superpowers/specs/2026-09-02-auora-ai-design.md). Read its section 1 first: it states what Auora is, what it is not, the verified platform facts it rests on, and the honest limits. Section 12 lists the sub-projects in build order; section 16 is the adversarial review log.

Planned 1.0: an open-source core on Windows (native), macOS and Linux.

## License

Apache-2.0. See [LICENSE](LICENSE).

## How this was made

The design was produced by the founder in a structured dialogue with Claude (Anthropic) and adversarially reviewed by OpenAI Codex; the review log with every finding and its resolution is in the specification. Every product decision is the founder's. Code in this repository is written with AI assistance and reviewed the same way, with the human merging.

## Development

- `pnpm verify` runs the dash check, typecheck and every test.
- `pnpm mutation-check` disables each security guard in turn and proves its test fails.
- `pnpm vitest run packages/<name>` runs one package's tests.
- Node 24 or newer and pnpm 10 are required.
