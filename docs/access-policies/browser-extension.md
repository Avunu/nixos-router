---
title: Browser extension
description: Show the block page for blocked HTTPS sites, instead of a certificate warning, with the nixos-router browser extension.
code:
  - pkgs/router-browser-extension/src/background.ts
  - pkgs/router-browser-extension/src/redirect.ts
  - pkgs/router-browser-extension/src/portal.ts
  - pkgs/router-browser-extension/src/errors.ts
  - pkgs/router-browser-extension/src/options.ts
  - pkgs/router-browser-extension/build.js
  - modules/cockpit-cert.nix
  - modules/reporting.nix
  - modules/dns-technitium.nix
  - pkgs/router-dns-tools/router_dns_tools/portal.py
  - pkgs/router-dns-tools/router_dns_tools/logd.py
  - pkgs/technitium-apps/RouterLiveDnsApp/App.cs
  - pkgs/cockpit-router/src/browser-extension.ts
  - pkgs/cockpit-router/src/access-policies.tsx
---

# Browser extension

Almost every site is HTTPS, and a browser can't show the [block page](/docs/access-policies/block-page/) for an HTTPS site: the router can't hold that site's certificate, so the browser shows a certificate warning instead. The **nixos-router Block Page** extension fixes this for Chrome, Edge, Brave and Firefox. When a secure site fails to open, it asks the router whether the site is blocked for this device, and if so shows the block page, from the router's own address with a trusted certificate.

## Before you start

- **The router needs a domain name.** Set **Domain name** on **System → Settings**. See [A trusted certificate](/docs/start/cockpit/#a-trusted-certificate). The extension talks to the router at `blocked.<your domain name>`, which gets its own Let's Encrypt certificate through Cloudflare DNS, like the domain name itself. That certificate is what lets the extension trust the router.
- **The block page must be on.** See [Turn on the block page](/docs/access-policies/block-page/#turn-on-the-block-page).
- **Apply both.** Then open **Access Policies → Block page** and check the **Browser extension** section. **Certificate** must show an issued certificate before browsers can pair.

## Install the extension

Install **nixos-router Block Page** from the Chrome Web Store (for Chrome, Edge and Brave) or from Firefox Add-ons. It asks for one permission, which browsers describe as reading your browsing history: it needs to notice when a page fails to load.

To build it yourself instead, run `nix build .#router-browser-extension` in the nixos-router repository. The result holds `chrome.zip`, `firefox.zip`, and both unpacked. Load the unpacked `chrome` folder with **Load unpacked** on `chrome://extensions` (with **Developer mode** on), or the `firefox/manifest.json` file on `about:debugging` under **This Firefox**.

## Pair it with the router

1. On **Access Policies → Block page**, copy the **Router address** from the **Browser extension** section, such as `blocked.gw.example.com:8068`.
2. Open the extension's options: click its toolbar button.
3. Paste the address under **Add router** and add it.
4. The browser asks to allow access to that one address. Allow it.

The extension checks that the address answers as a nixos-router, then lists it as connected with the router's host name. It can hold several routers, such as home and office, and asks them all at once.

Away from the router's networks, the router doesn't answer and the extension stays out of the way. The router only answers devices on its LAN, guest network and WireGuard tunnels.

## Deploy to managed browsers

A browser policy can pair the extension for every user. Install the extension with your usual policy, then add the router's address under the extension's own policy. **Access Policies → Block page** shows the Firefox policy for this router, ready to copy.

For Firefox, in `policies.json`:

```json
{
  "policies": {
    "3rdparty": {
      "Extensions": {
        "nixos-router@avu.nu": {
          "routers": ["https://blocked.gw.example.com:8068"]
        }
      }
    }
  }
}
```

For Chrome and Edge, the same `routers` list goes under `3rdparty` → `extensions` → the extension's id, in a managed policy file such as `/etc/opt/chrome/policies/managed/nixos-router.json` on Linux, or under `3rdparty\extensions\<id>\policy` in the Windows registry.

Browsers can't grant the extension access to the router through a policy. On install, the extension opens its options page, and the user clicks **Allow access** once.

## What users see

When a blocked secure site fails to open, the tab moves to the block page at the router's address, such as `https://blocked.gw.example.com:8068/portal/blocked?host=blocked.example.com`. It is the same page, with your texts and the **Request an exception** form, and the address shown is the blocked site. When the site was blocked by one of the standard filter lists or a category, the page names it, such as "Category: social networks".

- **NXDOMAIN policies still show no page.** They are meant for devices that should fail quietly, so the extension leaves those failures alone. See [Response](/docs/access-policies/policies/#response).
- **Back leaves the block page.** Pressing **Back** once shows the browser's own error for the blocked site; pressing it again goes back further.
- **Other failures are left alone.** A site that fails for any other reason, such as its own expired certificate, shows the browser's usual warning. The extension never gets past a certificate warning.

## How it works

- **It only reacts to failures.** The extension watches for a page that fails to load in a tab: a certificate or connection error, the way a blocked HTTPS site fails at the router. It ignores frames inside pages and pages loaded in the background.
- **The router decides.** The extension sends only the site's name, never the rest of the address, to `/portal/check` on the router, over HTTPS. `router-logd` asks the DNS server whether that name is blocked for the device asking, by its address, so the answer follows that device's own policy.
- **The page is on the router's own name.** The block page is served at `blocked.<domain name>` on port 8068, with its own Let's Encrypt certificate. It isn't on the domain name itself, where Cockpit is: browsers send Cockpit's login cookie to every port of that name.
- **It never uses plain HTTP.** Switching a blocked site to `http://` looks like the obvious fix, but browsers refuse it for sites that use HSTS, warn on `http://` by default, and a plain-HTTP page can't prove it came from the router. The extension only ever opens the router's HTTPS address.

The portal's port is `reporting.logd.tlsPort`, 8068 by default:

```json
{
  "reporting": {
    "logd": {
      "tlsPort": 8068
    }
  }
}
```

## Privacy

This is the extension's privacy policy.

- **What it reads.** The address of a page that fails to load in a tab. Nothing else about your browsing.
- **What it sends, and where.** Only the name of the site that failed to load, such as `blocked.example.com`, and only to the routers configured in the extension, over HTTPS. A router answers whether the site is blocked for the device asking.
- **What it keeps.** The routers you configured, in the browser's extension storage. Recent answers stay in memory for 30 seconds. While a tab shows the block page, the extension remembers that page's address until the tab moves on, so that **Back** works.
- **What it never does.** It sends nothing to the extension's developers or to anyone else, and uses no analytics.

The router itself logs DNS queries as your network administrator configured it. See [Reports](/docs/access-policies/reports/).

## Troubleshooting

- **The options page says the router isn't reachable.** Check that the device is on the router's network and that **Certificate** in the **Browser extension** section shows an issued certificate. From a device on the network, this should print the router's host name:

  ```bash
  curl -sH 'X-Router-Portal: 1' https://blocked.gw.example.com:8068/portal/info
  ```

- **A blocked site still shows a certificate warning.** Check that the extension lists the router as connected, and that the site is blocked by a **Blocking address** policy for that device: see [Preview a client](/docs/access-policies/assignments/#preview-a-client). After returning to the router's network, the extension can take up to 5 minutes to ask a router that didn't answer before.
- **The page says the router couldn't check the address.** `router-logd` couldn't reach the DNS server's check. See its log:

  ```bash
  journalctl -u router-logd | grep portal
  ```
