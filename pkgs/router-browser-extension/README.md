# nixos-router Block Page — browser extension

When a router blocks a site, its DNS answers the site's name with the router's
own LAN address. Over plain HTTP the router's Block Page app can answer, but
over HTTPS the browser sees a certificate for the router instead of the site
and shows a certificate error. This MV3 extension (Chrome, Edge, Brave and
Firefox) notices that failed navigation, asks the router over authenticated
HTTPS whether the host is blocked for this device, and if it is, sends the tab
to the router's block page on its own publicly trusted origin
(`https://blocked.<router domain>:8068/portal/blocked?host=…`).

It never downgrades to http, never proceeds past a certificate error, and never
navigates anywhere except a router portal the user or an administrator
configured. The only data that leaves the browser is the hostname of a page
that failed to load, sent to the configured router(s) and nowhere else.

User documentation:
<https://avunu.github.io/nixos-router/docs/access-policies/browser-extension/>

## Layout

| File                      | What it does                                                         |
| ------------------------- | -------------------------------------------------------------------- |
| `src/background.ts`       | Listener wiring (service worker on Chrome, event page on Firefox)    |
| `src/redirect.ts`         | The whole decision for a failed navigation — pure, unit-tested       |
| `src/errors.ts`           | Which `webNavigation` errors a block can cause                       |
| `src/host.ts`             | Hostname extraction; portal address normalization                    |
| `src/portal.ts`           | `/portal/info` and `/portal/check` client, 30 s cache, 5 min backoff |
| `src/config.ts`           | Router list: `storage.managed` (policy) ∪ `storage.sync` (user)      |
| `src/options.*`           | Options page: router status, pairing, granting access                |
| `src/managed-schema.json` | Chrome's schema for the `routers` policy                             |
| `build.js`                | esbuild per target, manifests, deterministic zips                    |
| `icons/icon.svg`          | Icon source; the PNGs are rendered from it once and committed        |

## Development

```sh
cd pkgs/router-browser-extension
nix develop ../..#router-browser-extension   # node_modules linked from Nix, plus web-ext
npm run build                                # dist/chrome/, dist/firefox/, dist/*.zip
npm run check                                # build, format, lint, type-aware lint, tsc, tests
web-ext lint --source-dir dist/firefox --self-hosted=false
```

The dev shell's `node_modules` is a read-only store path; for dependency bumps
run a plain `npm install` outside it (or `dontLinkNodeModules=1 nix develop …`).

From the repository root, `nix build .#router-browser-extension` builds the
same zips (`result/chrome.zip`, `result/firefox.zip`, plus the unpacked
directories) and `nix build .#checks.x86_64-linux.router-browser-extension`
runs `npm run check` and `web-ext lint`, as CI does. The zips are
byte-for-byte reproducible: sorted entries, fixed timestamps.

To re-render the icons after editing `icons/icon.svg`:

```sh
cd icons
nix shell nixpkgs#librsvg -c sh -c \
  'for s in 16 32 48 128; do rsvg-convert -w $s -h $s icon.svg -o icon-$s.png; done'
```

### Loading it unpacked

- **Chrome / Edge / Brave:** open `chrome://extensions` (`edge://extensions`,
  `brave://extensions`), turn on _Developer mode_, _Load unpacked_, and pick
  `dist/chrome`. After a rebuild, press the reload icon on the extension's card.
- **Firefox:** open `about:debugging#/runtime/this-firefox`, _Load Temporary
  Add-on…_, and pick `dist/firefox/manifest.json`. Or, from the dev shell,
  `web-ext run --source-dir dist/firefox`, which reloads on rebuild.

Then open the options page (click the toolbar icon), add the router's portal
address — e.g. `blocked.gw.example.com:8068` — and allow access when asked.

## Managed configuration (policy)

Administrators can preset routers. Policy-set routers appear on the options
page as "Set by your administrator" and cannot be removed there. Policy cannot
grant the host permission itself: each user still clicks _Allow access_ once;
the options page opens by itself after install when a policy router lacks it.
Addresses take the same forms as the options page (`https://` only; the port
defaults to 8068).

**Chrome / Chromium** — `3rdparty.extensions.<extension id>.routers`, e.g. on
Linux in `/etc/opt/chrome/policies/managed/nixos-router.json` (Chromium:
`/etc/chromium/policies/managed/`):

```json
{
  "3rdparty": {
    "extensions": {
      "<extension id>": {
        "routers": ["blocked.gw.example.com:8068"]
      }
    }
  }
}
```

**Firefox** — `policies.json` (`/etc/firefox/policies/policies.json` on Linux,
`distribution/policies.json` next to the Firefox binary elsewhere):

```json
{
  "policies": {
    "3rdparty": {
      "Extensions": {
        "nixos-router@avu.nu": {
          "routers": ["blocked.gw.example.com:8068"]
        }
      }
    }
  }
}
```

On a NixOS client the same is
`programs.firefox.policies."3rdparty".Extensions."nixos-router@avu.nu".routers`
and `programs.chromium.extraOpts."3rdparty".extensions."<extension id>".routers`.

## Store submission notes

- The bundles are unminified and carry no source maps, but they are generated
  (TypeScript bundled by esbuild), so AMO asks for the source: upload this
  directory with the build instructions `npm ci && npm run build` (Node 24).
- Firefox declares `data_collection_permissions: { required: ["none"] }`, which
  `web-ext lint` accepts. Mozilla defines data transmission as data "handled
  outside the add-on or the local browser", and the extension does send
  hostnames of failed pages to the user's own router; if AMO review considers
  that transmission, the fitting category is `browsingActivity` (change it in
  `build.js`).

## Manual verification checklist

Automated tests cover the decision logic; these need a real browser, a router
with its domain name set up, and a blocked HTTPS site.

- [ ] **Chrome fires `webNavigation.onErrorOccurred` on the cert interstitial.**
      Visiting a blocked HTTPS site shows the router's self-signed cert; confirm
      the event fires for frame 0 with `net::ERR_CERT_*` (e.g.
      `ERR_CERT_AUTHORITY_INVALID` / `ERR_CERT_COMMON_NAME_INVALID`), and that
      the tab lands on `https://blocked.<router>:8068/portal/blocked?host=…`.
- [ ] **Firefox fires on `about:certerror`**, and note the exact `error` string
      it reports (expected `Error code <decimal nsresult>`, e.g. 2153390067 for
      SEC_ERROR_UNKNOWN_ISSUER); confirm the redirect happens.
- [ ] **`tabs.update` can navigate away from the error page** in both browsers
      (`chrome-error://chromewebdata/` in Chrome, `about:certerror` in Firefox).
- [ ] **Typed bare host vs Chrome's HTTPS-Upgrades.** Type `blocked-site.example`
      (no scheme) in Chrome: HTTPS-Upgrades tries https first and falls back to
      http on failure. Check whether the extension's redirect wins, the http
      fallback reaches the router's plain-HTTP block page, or both race.
- [ ] **Back button after a redirect.** Chrome: Back returns to the certificate
      error once (the one-shot guard), a second Back leaves; reloading the error
      page redirects again. Firefox: `loadReplace` means Back skips the error
      page entirely.
- [ ] **Prerender is ignored.** With a page that speculation-rules-prerenders a
      blocked HTTPS URL, confirm no redirect happens until the user actually
      navigates there.
- [ ] **Chrome Local Network Access.** The extension's `fetch` to the portal
      (whose name resolves to a private LAN IP) must not be blocked or prompt;
      confirm pairing and checks work, and note any LNA prompt or console
      warning (host-permission holders are expected to be exempt).
- [ ] **Options page permission prompt** appears from the _Add router_ submit
      (both the button and Enter in the field) and from _Allow access_, in both
      browsers.
- [ ] **Managed policy.** With the policy JSON above, the router shows as "Set
      by your administrator", cannot be removed, and the options page opens on
      first install until access is granted.
- [ ] **Off-network.** Away from the router, failed pages are left alone and
      the options page shows "Not reachable — you may not be on this router's
      network."
