# Project intent: Auora AI

## What done looks like

A run labelled `protected` is provably contained: sandbox, hooks, resolver and proxy verified. Every promise in spec section 3.2 (`docs/superpowers/specs/2026-09-02-auora-ai-design.md`) has a test that fails when its guard is disabled. The hostile corpus is green on native Windows, macOS and Linux before anything is called 1.0.

## What I am optimising for

Correctness of the security boundary over speed and over feature count. A missing feature is acceptable; a silent gap in containment, a label that overclaims, or a default that fails open is not.

## What I will not accept

- New runtime dependencies without a one-line justification.
- Anything that fails open: daemon unreachable, log unwritable or sandbox missing must deny or refuse protected mode.
- Secrets in agent environments, logs or telemetry.
- Approvals not bound to the exact action digest.
- Behavior signals that grant permission.
- Claims in README or docs without a test or a cited primary source.
- Em dashes in any deliverable.

## Deliberately out of scope

- Kernel dataplane work (XDP, TC, DPDK) on any version.
- A hosted multi-tenant service, billing or team roles before the eight-week gate.
- Prompt-injection detection.
- SSH credential handling.
- Taint tracking of arbitrary child processes: labels cover what a door observed, and file-level denial is the primary control.

Reviewers should not re-raise these.
