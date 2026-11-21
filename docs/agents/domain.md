# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`README.md`**, **`DEPLOY.md`**, **`SECURITY.md`**, and **`AGENTS.md`** at the repo root.
- **`graphify-out/`** — query architecture and probe relationships.
- **`docs/adr/`** — read ADRs that touch the area you're about to work in.

If any of these files don't exist, proceed silently. Don't flag their absence; don't suggest creating them upfront.

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the exact probe terms defined in the codebase: `ping`, `traceroute`, `mtr`, `dns`, `http`, `tls`, `port`, `bandwidth`, `bgp`, `whois`, and the tri-state security policies (`public`, `homelab`, `unrestricted`).
