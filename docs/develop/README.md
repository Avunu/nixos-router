---
title: Development
description: Work on nixos-router itself, from the dev shell, checks and VM tests to the Cockpit plugin, the settings schema, these docs and CI.
nav_title: Develop
order: 9
code:
  - flake.nix
  - .envrc
  - lib/settings.nix
  - tests
  - tests/docs-lint.py
  - pkgs/cockpit-router/package.json
  - pkgs/cockpit-router/package.nix
  - pkgs/cockpit-router/build.js
  - pkgs/cockpit-router/src/schema.ts
  - pkgs/cockpit-router/src/router-settings.schema.json
  - .github/workflows/checks.yml
  - .github/workflows/schema-sync.yml
  - .github/workflows/dependabot-auto-merge.yml
---

# Development

This page is for people changing nixos-router itself: the NixOS modules, the Cockpit plugin, the packages or these docs. It covers the tools, the checks, and what CI requires before a change reaches routers.

## Repository layout

| Path | What it holds |
| --- | --- |
| `flake.nix` | The router module (`nixosModules.router`), the settings loader (`lib`), packages, dev shells, checks and the installer outputs. |
| `modules/` | One module per area, such as `network.nix`, `firewall.nix` and `dns-technitium.nix`. `topology.nix` computes the interface model the others share. |
| `lib/settings.nix` | The settings loader and its migrations. See [Settings migrations](settings-migrations.md). |
| `pkgs/` | `cockpit-router` (the web UI plugin), `router-dns-tools`, `router-proxy`, `suricata-update-preflight`, and the Technitium packages built from source: `technitium-dns-server`, `technitium-library` and `technitium-apps`. |
| `tests/` | Evaluation checks and NixOS VM tests. |
| `local/` | The host flake template, `deploy.sh`, and example settings. |
| `docs/` | These docs, in Markdown. The shared documentation site at docs.avunu.net builds and publishes them; see [Working on these docs](#working-on-these-docs). |

## The dev shell

```bash
nix develop
```

The shell provides `nixd`, `nixfmt`, `prek` and `update-deps`, and installs a pre-commit hook that formats `.nix` files with nixfmt. With direnv, `.envrc` enters it for you.

`update-deps` refreshes the pins in one go. It moves the two Technitium source inputs, `technitium-dns` and `technitium-library`, to the latest upstream release together, runs `nix flake update`, checks that the two refs are one release, and regenerates the NuGet locks of the three packages built from them: `pkgs/technitium-library`, `pkgs/technitium-dns-server` and `pkgs/technitium-apps`. Pass `--keep-technitium` to refresh the locks without changing the release.

The DNS server is compiled from those inputs, not taken from nixpkgs, so it moves independently of nixpkgs. See [Technitium DNS Server build](#the-technitium-dns-server-build) for what the build changes.

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
| `technitium-version` | Evaluation | The `technitium-dns` and `technitium-library` refs are one release. |
| `ddns-cloudflare`, `cloudflare-tunnel` | Sandbox | `router-ddns` and the tunnel manager against a fake Cloudflare API. |
| `suricata-update-preflight` | Sandbox | The Suricata rule-update self-heal. |
| `technitium-server` | Sandbox | The compiled DNS server and apps are ReadyToRun images, carry the runtime feature switches, and ship no web console. |
| `docs-lint` | Sandbox | The docs' front matter and the source paths a page's `code` list names, text a colon would delete, and images with no alt text. |
| `cockpit-router` | Sandbox | The plugin's formatting, lint, type checks and unit tests. |
| `router-schema-fresh` | Sandbox | The committed settings schema matches the options (x86_64 only). |
| `technitium-vm` | VM | Filtering policies, static leases, the query log, the block page and reports. |
| `guest-access-vm` | VM | LAN to guest works one way only, with and without Suricata, and a remote site reaches the LAN through a WireGuard tunnel. |
| `port-forwards-vm` | VM | IPv4 DNAT, IPv6 pinholes, source restrictions and dynamic DNS on the wire. |
| `reverse-proxy-vm` | VM | Certificate issuance, HTTPS by name, redirects, hairpin from the LAN and guest, the block page kept out of the hairpin, and reloads. |
| `suricata-vm` | VM | The IPS inline end to end. |
| `wireless-podman-vm` | VM | The container network survives an nftables reload. |

## The Technitium DNS Server build

The router compiles the DNS server from source instead of taking nixpkgs' package, so it can run a Technitium release that nixpkgs doesn't carry yet. Three packages are built from two flake inputs:

| Package | Built from |
| --- | --- |
| `technitium-dns-server-library` (`pkgs/technitium-library`) | The `technitium-library` input: TechnitiumLibrary at `dns-server-vX.Y.Z`. |
| `technitium-dns-server` (`pkgs/technitium-dns-server`) | The `technitium-dns` input: DnsServer at `vX.Y.Z`. |
| `technitium-dns-apps` (`pkgs/technitium-apps`) | The same `technitium-dns` tree, plus the router's own Router Live DNS app. |

The router overlay replaces nixpkgs' `technitium-dns-server` and `technitium-dns-server-library` with these, so nothing from nixpkgs' Technitium package reaches a router. The version is read from the source's own project file. The two refs must name one release: `technitium-version` fails when they don't, and `update-deps` moves them together.

The build options are in `pkgs/technitium-dns-server/build-options.nix` and apply to the server and the apps alike:

| Option | What it does |
| --- | --- |
| ReadyToRun | Ships precompiled native code beside the IL. The server restarts whenever its closure changes, and LAN clients have no DNS until it is back. On a test machine limited to four cores it took its first API call about 17% sooner (396 to 328 ms), answered its first query in 1 ms instead of 4, and served the first zone and record API calls 2.5 to 4 times faster. Throughput at saturation is the same within run-to-run noise: the unoptimised build was ahead by 1 to 3% in the median of three runs, while a single build varied by 10% from one run to the next. |
| No EventSource, no Meters | Nothing here collects runtime telemetry, so the providers are off in `runtimeconfig.json`. |
| Invariant globalization | libicu is never loaded and string handling no longer depends on the process locale. It saves about 10 MB of resident memory. The cost is that converting non-ASCII names to punycode through the API can differ from the ICU result (an upper-case `BÜCHER.de`, for example). The router only sends ASCII names, and names on the wire are already punycode. |

The web console is left out. `www/` (the console) and `dohwww/` (the DNS-over-HTTPS landing page) are emptied after the build, not removed, because the web service fails to start without the directories. The HTTP API is separate from those files and is what the router and Cockpit use. Without the console, nothing calls the server's update check either. The start-up banner in the journal still says to open the web console in a browser; that text is hard-coded upstream, and patching it would make each release bump fragile.

`technitium-server` guards all of this in the build output: every assembly is a ReadyToRun image, the feature switches are in `runtimeconfig.json`, and no web file is left beside the daemon. It fails if any of them stops being true.

Some options were tried or considered and left alone:

- **Trimming and NativeAOT** can't work: the server loads the apps by reflection at run time.
- **Self-contained publishing** would freeze the .NET runtime in the closure. It now comes from nixpkgs and is updated with the system.
- **Server garbage collection** gave no reliable throughput gain in testing (runs ranged from 194k to 257k queries per second) and raised peak memory by about 10 MB. The upstream project file sets `ServerGarbageCollection` in a class library, which never reaches the server's own `runtimeconfig.json`, so the shipped server has always used workstation GC.
- **Non-concurrent GC** raised peak memory, from about 134 MB to 182 MB, for no speed.
- **Turning tiered PGO off** starts about 27 ms sooner and loses about 5% of throughput.

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

If the change renames, removes or reshapes an option that settings files can hold, it also needs a migration. See [Settings migrations](settings-migrations.md).

## Working on these docs

The docs are Markdown files in `docs/`. `docs/README.md` is the home page, a folder is a section of the sidebar, and a folder's `README.md` is that section's overview. A page's address is its path under `docs/` without `.md`: `docs/network/hosts.md` is `/nixos-router/docs/network/hosts/` on [docs.avunu.net](https://docs.avunu.net/nixos-router/docs/).

Every page opens with front matter:

| Key | Meaning |
| --- | --- |
| `title` | The page title. Required. |
| `description` | One sentence, shown in search results and link previews. Required. |
| `nav_title` | A shorter name for the sidebar. On a section's `README.md` it names the section. |
| `order` | A number: lower comes first, and pages without one come last, alphabetically. |
| `code` | The source files the page describes. Each one must exist. |

There is no separate sidebar file: the sidebar is made from the folders and these keys.

The site is not built from this repository. [Avunu/site-docs](https://github.com/Avunu/site-docs) holds every Avunu project as a git submodule and builds all of their `docs/` folders into one site, with one look, one search and one project menu. It follows this project's latest release, so a docs change goes live with the next release.

To preview a change, clone site-docs beside this repository and build it with your working copy in place of the submodule. You need Node 22.19 or newer:

```bash
git clone https://github.com/Avunu/site-docs
cd site-docs
npm ci --ignore-scripts
npm run build
node build/cli.js build --lenient --only nixos-router --source nixos-router=../nixos-router
python3 -m http.server --directory dist 8000
```

Then open `http://localhost:8000/nixos-router/docs/`. `--lenient` prints document problems as warnings and still builds. Before you push, run the strict build that the site itself runs, which also crawls every link and anchor:

```bash
node build/cli.js check --only nixos-router --source nixos-router=../nixos-router
```

The site's [guide to writing documentation](https://docs.avunu.net/site-docs/docs/guide/writing-docs/) has the full conventions. The ones that matter most here:

- **Link between pages with relative file links,** such as `../ingress/reverse-proxy.md#choose-a-challenge`. The site rewrites them to addresses. Never write an address that starts with `/docs/`: it points at the root of the shared site, not at this project.
- **Callouts use GitHub's alerts:** `> [!NOTE]`, `> [!TIP]` or `> [!WARNING]`.
- **Diagrams are SVG files in `docs/images/`,** and every image has alt text.
- **A colon directly followed by a letter or digit starts a directive,** which deletes the text after it, with no warning and a passing build. So a host and port such as `vpn.example.com:51820`, a time such as `03:00`, or an IPv6 address always goes in inline code or a code block. A colon followed by a space is fine.
- **Reference-style links and footnotes do not render.** Write inline links.

The `docs-lint` check enforces the front matter, the colon rule and the alt text, because the site cannot: it does not know this repository's paths, and it builds a page with a deleted word or an empty `alt` without complaint. It runs in CI's fast job, with the other sandbox checks. Everything else about a page is checked by the site.

## Branches and releases

Changes land on `develop`, the default branch. Open pull requests against `develop` and squash-merge them under a conventional title, such as `feat: ...`, `fix: ...` or `docs: ...`. The title becomes the commit subject, and the changelog is written from it. A breaking change takes `!` after the type, as in `feat!: ...`, or a `BREAKING CHANGE:` footer.

`release.yml` keeps one release pull request open against `develop`, titled `chore: release` with the next version, and enables auto-merge on it. Merging it creates the tag, the GitHub release, `CHANGELOG.md` and `version.txt`. The tagged release then runs the same checks as `develop`, with its binary cache published. Only if they pass is `main` fast-forwarded to the tag. A failed gate leaves `main` on the previous release and opens a `release-incomplete` issue.

`main` is the release branch. Routers follow it, and nothing else is pushed to it. Until 1.0, features and breaking changes both raise the minor version, and fixes raise the patch.

Dependabot pull requests target `develop` as well. Updates to the Nix inputs and to the Cockpit and Rust lockfiles are titled `fix(deps)`, so they reach routers through a release. Updates to the workflows are `chore`, and release nothing.

The release pull request is refreshed on every push to `develop`, and once a day at `00:30` UTC, which picks up Dependabot merges. Routers upgrade from `main` at `03:00`, so a release reaches them on the first upgrade after it passes its gate.

Four things live in the repository settings rather than in the code. Each is set once:

- **Auto-merge** is allowed under Settings → General → Pull Requests. Merging is squash-only, with the pull request title as the commit subject.
- **A ruleset on `develop`** requires a pull request and the checks **drift + build (fast)**, **VM tests (slow)** and **pr title**.
- **A ruleset on `main`** blocks deletion, force pushes and direct pushes. The owner of the release token is on its bypass list. Create it before `develop` becomes the default branch.
- **The `RELEASE_TOKEN` secret** is a fine-grained personal access token for this repository, with write access to contents, pull requests, issues and workflows. The default `GITHUB_TOKEN` cannot do this job: the pull requests it opens get no checks, it cannot bypass a ruleset, and its pushes start no workflows.

## Continuous integration

`.github/workflows/checks.yml` runs on every pull request, on every push to `develop`, nightly at `02:41` UTC, and on demand. It is also the release gate: `release.yml` calls it at each release tag. It has three jobs:

- **drift + build (fast):** builds the evaluation checks, the sandbox checks except `suricata-update-preflight`, the plugin's checks and the plugin package. It gives a verdict in minutes.
- **VM tests (slow):** runs `nix flake check`, which boots the VM tests.
- **build + publish binary cache:** builds the install system and the router packages, and pushes everything cache.nixos.org doesn't have to nixos-router.cachix.org. It publishes only when the release gate asks for it, never from a pull request or a `develop` run. The `CACHIX_AUTH_TOKEN` secret belongs in Actions secrets only.

The other workflows:

- **`schema-sync.yml`** regenerates a stale settings schema on pull requests, as described above.
- **`dependabot-auto-merge.yml`** turns on auto-merge for every Dependabot pull request, Nix lock bumps included.
- **`release.yml`** and **`pr-title.yml`** are described under Branches and releases above.

The workflows rely on a ruleset on `develop`, set in the repository settings rather than in the code, that requires a pull request and the checks **drift + build (fast)**, **VM tests (slow)** and **pr title**. It matters because there is no human review step for dependency bumps: a Dependabot pull request merges as soon as the required checks pass, and routers upgrade from `main` once a release carries the change there. The tests are the gate.
