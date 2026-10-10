---
title: Development
description: Work on nixos-router itself, from the dev shell, checks and VM tests to the Cockpit plugin, the settings schema, these docs and CI.
code:
  - flake.nix
  - .envrc
  - lib/settings.nix
  - tests
  - pkgs/cockpit-router/package.json
  - pkgs/cockpit-router/package.nix
  - pkgs/cockpit-router/build.js
  - pkgs/cockpit-router/src/schema.ts
  - pkgs/cockpit-router/src/router-settings.schema.json
  - site/package.json
  - site/scripts/lint-docs.ts
  - docs/nav.json
  - .github/workflows/checks.yml
  - .github/workflows/schema-sync.yml
  - .github/workflows/site.yml
  - .github/workflows/dependabot-auto-merge.yml
---

# Development

This page is for people changing nixos-router itself: the NixOS modules, the Cockpit plugin, the packages or these docs. It covers the tools, the checks, and what CI requires before a change reaches routers.

## Repository layout

| Path | What it holds |
| --- | --- |
| `flake.nix` | The router module (`nixosModules.router`), the settings loader (`lib`), packages, dev shells, checks and the installer outputs. |
| `modules/` | One module per area, such as `network.nix`, `firewall.nix` and `dns-technitium.nix`. `topology.nix` computes the interface model the others share. |
| `lib/settings.nix` | The settings loader and its migrations. See [Settings migrations](/docs/develop/settings-migrations/). |
| `pkgs/` | `cockpit-router` (the web UI plugin), `router-dns-tools`, `router-proxy`, `technitium-apps` and `suricata-update-preflight`. |
| `tests/` | Evaluation checks and NixOS VM tests. |
| `local/` | The host flake template, `deploy.sh`, and example settings. |
| `docs/`, `site/` | These docs, and the site that publishes them. |

## The dev shell

```bash
nix develop
```

The shell provides `nixd`, `nixfmt`, `prek` and `update-deps`, and installs a pre-commit hook that formats `.nix` files with nixfmt. With direnv, `.envrc` enters it for you.

`update-deps` refreshes the pins in one go. It runs `nix flake update`, checks that the Technitium DNS apps input still matches the Technitium server version in nixpkgs, and regenerates `pkgs/technitium-apps/nuget-deps.json`. When the versions have drifted, bump the `technitium-dns` input's tag in `flake.nix` by hand and run it again.

## Checks and VM tests

Build a single check with:

```bash
nix build .#checks.x86_64-linux.settings-loader
```

Run every check, including the VM tests, with `nix flake check`. The VM tests boot real routers in QEMU and need KVM.

| Check | Kind | What it guards |
| --- | --- | --- |
| `settings-loader` | Evaluation | Old settings are upgraded, current ones are left alone, and the file is rewritten at activation. |
| `port-forwards-eval` | Evaluation | The nftables rules each port forward produces, and every misconfiguration rejected by name. |
| `ingress-eval` | Evaluation | Reverse proxy redirects, certificates, tunnel ingress, and name clashes between features. |
| `wireguard-eval` | Evaluation | Each WireGuard tunnel's network unit (forwarding, reverse-path filter, routes, address) and Cockpit accepting the tunnel address, IPv6 included, run through the `fnmatch()` match Cockpit makes. |
| `dns-fallback` | Evaluation | Something always answers DNS on the LAN, even with Technitium off. |
| `dns-overrides` | Evaluation | Split-horizon DNS: which zone each record lands in. |
| `wireless-eval` | Evaluation | The UniFi and OpenWISP controllers' wiring. |
| `suricata-eval` | Evaluation | Suricata's config file and log rotation, suppression addresses, and the build-time rule test failing on a broken rule and turning off with `checkRulesAtBuild`. |
| `technitium-version` | Evaluation | The Technitium apps input matches the DNS server in nixpkgs. |
| `ddns-cloudflare`, `cloudflare-tunnel` | Sandbox | `router-ddns` and the tunnel manager against a fake Cloudflare API. |
| `suricata-update-preflight` | Sandbox | The Suricata rule-update self-heal. |
| `cockpit-router` | Sandbox | The plugin's formatting, lint, type checks and unit tests. |
| `router-schema-fresh` | Sandbox | The committed settings schema matches the options (x86_64 only). |
| `technitium-vm` | VM | Filtering policies, static leases, the query log, the block page and reports. |
| `guest-access-vm` | VM | LAN to guest works one way only, with and without Suricata, and a remote site reaches the LAN through a WireGuard tunnel. |
| `port-forwards-vm` | VM | IPv4 DNAT, IPv6 pinholes, source restrictions and dynamic DNS on the wire. |
| `reverse-proxy-vm` | VM | Certificate issuance, HTTPS by name, redirects, hairpin from the LAN and guest, the block page kept out of the hairpin, and reloads. |
| `suricata-vm` | VM | The IPS inline end to end. |
| `wireless-podman-vm` | VM | The container network survives an nftables reload. |

## The Cockpit plugin

The plugin lives in `pkgs/cockpit-router`: React with PatternFly, bundled by esbuild. Work on it in its own shell:

```bash
cd pkgs/cockpit-router
nix develop ../..#cockpit-router
npm run check
```

The shell links `node_modules`, built from `package-lock.json`, and `pkg/lib`, Cockpit's own shared library from the same Cockpit package the router runs. `npm run check` builds the bundle and runs the formatter check, oxlint, type-aware oxlint, `tsc` and the unit tests; CI runs the same suite as the `cockpit-router` check.

Other scripts: `npm run build` writes the bundle to `dist/`, `npm run watch` builds a development bundle, and `npm run format` and `npm run lint:fix` fix what they can.

`node_modules` is read-only in the shell, so dependency bumps (`npm run upgrade`) need a writable copy. Enter the shell with `dontLinkNodeModules=1 nix develop ../..#cockpit-router`, or run `npm install` outside it.

On a router, the plugin reads a per-router `config.js` that the module generates, with the Technitium and `router-logd` ports, the host name, the flake path and the settings file path.

## The settings schema

The web UI validates the settings file against `pkgs/cockpit-router/src/router-settings.schema.json`. The schema is generated from the `router.*` options, so it is a build output, not something you edit. Options marked `visible = false`, such as `router.cockpit.*`, and options that take Nix packages are left out. `build.js` compiles the schema into a standalone Ajv validator, because Cockpit's content security policy forbids the code generation Ajv normally does at runtime.

After changing an option, regenerate the schema:

```bash
nix build .#packages.x86_64-linux.settingsSchema-router \
  && jq -S . result > pkgs/cockpit-router/src/router-settings.schema.json
```

If you forget, the `router-schema-fresh` check fails with `router-settings.schema.json is stale vs router.* options — regenerate it.` On a pull request from a branch of this repository, the `schema-sync` workflow regenerates the file and pushes the fix to your branch as `chore(schema): regenerate stale router-settings.schema.json`. Pull requests from forks have to regenerate it by hand.

If the change renames, removes or reshapes an option that settings files can hold, it also needs a migration. See [Settings migrations](/docs/develop/settings-migrations/).

## Working on these docs

The docs are Markdown files in `docs/`, one per page. A page's address is its path under `docs/` without `.md`: `docs/network/hosts.md` is `/docs/network/hosts/`. The sidebar is `docs/nav.json`, and every page must be listed there. The site in `site/` is a [Jx](https://jxsuite.com) project that reads the pages from `docs/`.

Install the site's dependencies once, then preview with live reload:

```bash
cd site
bun install
bun run dev
```

`bun install` also installs `oxfmt`, a development dependency the Jx dev server needs. `bun run dev` bundles the search client, which isn't committed, and then runs `jx dev`; `bunx jx dev` on its own leaves search broken. To preview a production build, run `bun run build`, then `bun run preview`.

Before you push, run the checks from `site/`:

```bash
bun run lint
bun run check
```

`bun run lint` runs the docs linter, `scripts/lint-docs.ts`. `bun run check` runs `jx schema`, `jx validate`, the linter and the build, most of what CI's **site build** job runs.

The linter checks each page's frontmatter (`title`, `description`, and that the paths listed under `code` exist), that the H1 matches the title, links and heading anchors between pages, image paths and alt text, and that `docs/nav.json` and the pages agree.

Two Markdown rules of Jx break pages without any warning, and the linter catches both:

- **Never write a dollar sign directly followed by an opening curly brace,** anywhere in a page, code blocks included. Jx evaluates that sequence as a template expression in the browser, and there is no way to escape it. Write shell variables as `$VAR`, and show Nix without string interpolation.
- **A colon directly followed by a letter or digit starts a directive,** which swallows the text after it. So a host and port such as `vpn.example.com:51820`, a time such as `03:00`, an IPv6 address such as `::10`, or a URL with a port always goes in inline code or a code block. A colon followed by a space is fine.

Link between pages with site-absolute paths and a trailing slash, such as `/docs/ingress/reverse-proxy/`, never with relative `.md` links. Diagrams are SVG files in `docs/images/`.

## Branches and releases

Changes land on `develop`, the default branch. Open pull requests against `develop` and squash-merge them under a conventional title, such as `feat: ...`, `fix: ...` or `docs: ...`. The title becomes the commit subject, and the changelog is written from it. A breaking change takes `!` after the type, as in `feat!: ...`, or a `BREAKING CHANGE:` footer.

`release.yml` keeps one release pull request open against `develop`, titled `chore: release` with the next version, and enables auto-merge on it. Merging it creates the tag, the GitHub release, `CHANGELOG.md` and `version.txt`. The tagged release then runs the same checks as `develop`, with its binary cache published. Only if they pass is `main` fast-forwarded to the tag. A failed gate leaves `main` on the previous release and opens a `release-incomplete` issue.

`main` is the release branch. Routers follow it, and nothing else is pushed to it. Until 1.0, features and breaking changes both raise the minor version, and fixes raise the patch.

Dependabot pull requests target `develop` as well. Updates to the Nix inputs and to the Cockpit and Rust lockfiles are titled `fix(deps)`, so they reach routers through a release. Updates to the docs site and to the workflows are `chore`, and release nothing.

The release pull request is refreshed on every push to `develop`, and once a day at `00:30` UTC, which picks up Dependabot merges. Routers upgrade from `main` at `03:00`, so a release reaches them on the first upgrade after it passes its gate.

Four things live in the repository settings rather than in the code. Each is set once:

- **Auto-merge** is allowed under Settings → General → Pull Requests. Merging is squash-only, with the pull request title as the commit subject.
- **A ruleset on `develop`** requires a pull request and the checks **drift + build (fast)**, **VM tests (slow)**, **site build** and **pr title**.
- **A ruleset on `main`** blocks deletion, force pushes and direct pushes. The owner of the release token is on its bypass list. Create it before `develop` becomes the default branch.
- **The `RELEASE_TOKEN` secret** is a fine-grained personal access token for this repository, with write access to contents, pull requests, issues and workflows. The default `GITHUB_TOKEN` cannot do this job: the pull requests it opens get no checks, it cannot bypass a ruleset, and its pushes start no workflows.

## Continuous integration

`.github/workflows/checks.yml` runs on every pull request, on every push to `develop`, nightly at `02:41` UTC, and on demand. It is also the release gate: `release.yml` calls it at each release tag. It has three jobs:

- **drift + build (fast):** builds the evaluation checks, the sandbox checks except `suricata-update-preflight`, the plugin's checks and the plugin package. It gives a verdict in minutes.
- **VM tests (slow):** runs `nix flake check`, which boots the VM tests.
- **build + publish binary cache:** builds the install system and the router packages, and pushes everything cache.nixos.org doesn't have to nixos-router.cachix.org. It publishes only when the release gate asks for it, never from a pull request or a `develop` run. The `CACHIX_AUTH_TOKEN` secret belongs in Actions secrets only.

The other workflows:

- **`schema-sync.yml`** regenerates a stale settings schema on pull requests, as described above.
- **`site.yml`** builds the docs site on every pull request and deploys to GitHub Pages on every push to `main`. Its job is called **site build**.
- **`dependabot-auto-merge.yml`** turns on auto-merge for every Dependabot pull request, Nix lock bumps included.
- **`release.yml`** and **`pr-title.yml`** are described under Branches and releases above.

The workflows rely on a ruleset on `develop`, set in the repository settings rather than in the code, that requires a pull request and the checks **drift + build (fast)**, **VM tests (slow)**, **site build** and **pr title**. It matters because there is no human review step for dependency bumps: a Dependabot pull request merges as soon as the required checks pass, and routers upgrade from `main` once a release carries the change there. The tests are the gate.
