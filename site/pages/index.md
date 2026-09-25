---
title: "nixos-router: a small-business router you configure in a browser and rebuild like code"
$head:
  - tagName: meta
    attributes:
      name: description
      content: "A NixOS module and a Cockpit web UI that turn a multi-NIC machine into a small-business router: DNS filtering policies, Suricata IPS, reverse proxy with Let's Encrypt, Cloudflare dynamic DNS and WireGuard site-to-site VPN."
  - tagName: meta
    attributes:
      property: "og:title"
      content: "nixos-router"
  - tagName: meta
    attributes:
      property: "og:description"
      content: "A small-business router you configure in a browser and rebuild like code."
$elements:
  - $ref: ../components/nr-cta.json
  - $ref: ../components/nr-feature.json
  - $ref: ../components/nr-guide-card.json
  - $ref: ../components/nr-code-panel.json
---

::::::section{style.padding="clamp(3.5rem, 9vw, 6.5rem) clamp(1rem, 3vw, 2rem) clamp(2.5rem, 6vw, 4rem)" style.background="linear-gradient(180deg, var(--color-accent-soft), var(--color-bg-primary))" style.borderBottom="1px solid var(--color-border-subtle)"}
:::::div{style.maxWidth="var(--max-width)" style.margin="0 auto" style.display="grid" style.gridTemplateColumns="minmax(0, 1.1fr) minmax(0, 0.9fr)" style.gap="clamp(2rem, 5vw, 4rem)" style.alignItems="center" style.--lg.gridTemplateColumns="minmax(0, 1fr)"}
::::div
:::h1{style.fontSize="clamp(2.25rem, 5.5vw, 3.6rem)" style.fontWeight="700" style.margin="0 0 1.25rem"}
A small-business router you configure in a browser and rebuild like code.
:::

:::p{style.fontSize="clamp(1.0625rem, 2vw, 1.25rem)" style.color="var(--color-text-secondary)" style.lineHeight="1.6" style.margin="0 0 2rem" style.maxWidth="620px"}
nixos-router turns a multi-NIC machine into a router for an office, a school or a serious home network. Filter DNS per group, inspect traffic with Suricata, publish services with real certificates and join sites over WireGuard, all from a Cockpit web UI. Every change is a NixOS rebuild you can roll back.
:::

:::div{style.display="flex" style.gap="0.75rem" style.flexWrap="wrap"}
::nr-cta{props.href="/docs/start/" props.label="Get started" props.variant="primary"}
::nr-cta{props.href="/docs/" props.label="Read the docs" props.variant="secondary"}
::nr-cta{props.href="https://github.com/Avunu/nixos-router" props.label="GitHub" props.variant="secondary" props.newTab="true"}
:::
::::

::::nr-code-panel{props.label="/etc/nixos/router-settings.json"}

```json
{
  "hostName": "office-gw",
  "hostGroups": [{ "name": "classroom" }],
  "accessPolicies": {
    "defaultPolicy": "Staff",
    "policies": [
      {
        "name": "Staff",
        "standardFilters": ["adguard_malware"]
      },
      {
        "name": "Students",
        "categories": ["gambling", "games"],
        "assignments": {
          "hostGroups": ["classroom"]
        }
      }
    ]
  },
  "suricata": { "enable": true, "mode": "ips" }
}
```

::::
:::::
::::::

:::::section{style.padding="clamp(3rem, 7vw, 5rem) clamp(1rem, 3vw, 2rem)"}
::::div{style.maxWidth="var(--max-width)" style.margin="0 auto"}
:::h2{style.fontSize="clamp(1.6rem, 3vw, 2.1rem)" style.margin="0 0 0.5rem"}
What it does
:::

:::p{style.color="var(--color-text-secondary)" style.margin="0 0 1.75rem" style.maxWidth="680px"}
One NixOS module, one settings file, one web UI. Everything below is configured from Cockpit and applied together.
:::

:::div{style.display="grid" style.gridTemplateColumns="repeat(auto-fit, minmax(min(270px, 100%), 1fr))" style.gap="0.85rem"}
::nr-feature{props.title="Networks and VLANs" props.text="WAN over DHCP with IPv6 prefix delegation, a LAN and an isolated guest network, VLAN trunks, DHCP reservations and router advertisements."}
::nr-feature{props.title="Access policies" props.text="DNS filtering on Technitium with named policies per host group, directory group, subnet or network. Category lists, curated filters, and a block page where users can request exceptions."}
::nr-feature{props.title="Threat protection" props.text="Suricata inspects forwarded traffic against ET Open and other open rule sets. Start alert-only, tune categories and signatures from the event list, then let it drop."}
::nr-feature{props.title="Ingress" props.text="Port forwards over IPv4 and IPv6, a hostname-routing reverse proxy with Let's Encrypt certificates, or a Cloudflare Tunnel when the router sits behind CGNAT."}
::nr-feature{props.title="Dynamic DNS" props.text="Cloudflare A and AAAA records for the router and for individual devices, kept current as addresses change, with carrier-grade NAT detected for you."}
::nr-feature{props.title="WireGuard" props.text="Site-to-site tunnels between offices and remote access for laptops and phones, with keys generated on the router."}
::nr-feature{props.title="Reports" props.text="DNS dashboards per group, device and user, the full query log, and scheduled PDF reports that can be emailed, each with a CSV copy."}
::nr-feature{props.title="Directory integration" props.text="Map devices to users and policies to groups from LDAP, Active Directory, Google Secure LDAP or Entra Domain Services."}
::nr-feature{props.title="Wireless controllers" props.text="Optionally run a UniFi Network Application or OpenWISP on the router itself to manage your access points."}
::nr-feature{props.title="Safe upgrades" props.text="Nightly upgrades pulled from a binary cache that CI builds and tests, and every change is a NixOS generation you can roll back to."}
:::
::::
:::::

::::::section{style.padding="clamp(3rem, 7vw, 5rem) clamp(1rem, 3vw, 2rem)" style.backgroundColor="var(--color-bg-secondary)" style.borderTop="1px solid var(--color-border-subtle)" style.borderBottom="1px solid var(--color-border-subtle)"}
:::::div{style.maxWidth="var(--max-width)" style.margin="0 auto" style.display="grid" style.gridTemplateColumns="minmax(0, 0.85fr) minmax(0, 1.15fr)" style.gap="clamp(2rem, 5vw, 4rem)" style.alignItems="center" style.--lg.gridTemplateColumns="minmax(0, 1fr)"}
::::div
:::h2{style.fontSize="clamp(1.6rem, 3vw, 2.1rem)" style.margin="0 0 1rem"}
How it works
:::

1. **Edit in Cockpit.** Every page writes to one file, `router-settings.json`, and checks it against the settings schema before saving.
2. **Apply.** NixOS rebuilds the router from that file. DNS, firewall rules and services are all generated from it.
3. **Roll back.** Every apply is a new generation. If a change goes wrong, the System page or the boot menu takes you back to the last good one.

:::p{style.color="var(--color-text-secondary)"}
You never have to write Nix to run a router. When you want to, the same settings are NixOS options, and anything you set in Nix locks the matching field in the UI.
:::
::::

::::div{style.minWidth="0"}
![Cockpit writes router-settings.json; nixos-rebuild turns it into DNS, firewall and service configuration; earlier generations stay available for rollback.](/content/docs/images/architecture.svg)
::::
:::::
::::::

:::::section{style.padding="clamp(3rem, 7vw, 5rem) clamp(1rem, 3vw, 2rem)"}
::::div{style.maxWidth="var(--max-width)" style.margin="0 auto"}
:::h2{style.fontSize="clamp(1.6rem, 3vw, 2.1rem)" style.margin="0 0 0.5rem"}
Guides for the advanced features
:::

:::p{style.color="var(--color-text-secondary)" style.margin="0 0 1.75rem" style.maxWidth="680px"}
Step-by-step instructions in the web UI, the settings each step writes, how it works on the router, and the limits you should know before relying on it.
:::

:::div{style.display="grid" style.gridTemplateColumns="repeat(auto-fit, minmax(min(300px, 100%), 1fr))" style.gap="1rem"}
::nr-guide-card{props.href="/docs/access-policies/" props.kicker="DNS filtering" props.title="Access policies" props.text="Build policies from category lists and filters, assign them to devices, groups and networks, and handle exception requests."}
::nr-guide-card{props.href="/docs/threat-protection/" props.kicker="Suricata IDS / IPS" props.title="Threat protection" props.text="Turn on inspection, triage events into rule policies and suppressions, and move from alert-only to blocking."}
::nr-guide-card{props.href="/docs/dynamic-dns/" props.kicker="Cloudflare" props.title="Dynamic DNS" props.text="Publish the router and individual devices under your own domain, over IPv4 and IPv6, even behind carrier-grade NAT."}
::nr-guide-card{props.href="/docs/ingress/" props.kicker="Publish services" props.title="Ingress" props.text="Choose between port forwards, the reverse proxy with Let's Encrypt certificates, and Cloudflare Tunnel, then set one up."}
::nr-guide-card{props.href="/docs/wireguard/site-to-site/" props.kicker="VPN" props.title="WireGuard site-to-site" props.text="Join two offices' LANs over a WireGuard tunnel, step by step on both routers, and understand the routing it relies on."}
::nr-guide-card{props.href="/docs/start/install/" props.kicker="Start here" props.title="Install a router" props.text="Install over the network with nixos-anywhere or from the installer, then log in to Cockpit and apply your first change."}
:::
::::
:::::

:::::section{style.padding="0 clamp(1rem, 3vw, 2rem) clamp(4rem, 8vw, 6rem)"}
::::div{style.maxWidth="var(--max-width)" style.margin="0 auto" style.padding="clamp(1.75rem, 4vw, 2.75rem)" style.boxSizing="border-box" style.borderRadius="var(--radius-lg)" style.border="1px solid var(--color-border)" style.backgroundColor="var(--color-bg-secondary)" style.display="flex" style.flexWrap="wrap" style.gap="1.5rem" style.alignItems="center" style.justifyContent="space-between"}
:::div{style.maxWidth="640px"}
**Two ways to install.** Install over SSH with `local/deploy.sh`, which uses nixos-anywhere, or build an installer image and install offline from a USB stick. Both leave a host flake and your settings file in `/etc/nixos`.
:::

::nr-cta{props.href="/docs/start/install/" props.label="Install guide" props.variant="primary"}
::::
:::::
