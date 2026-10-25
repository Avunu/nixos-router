---
title: nixos-router documentation
description: Guides for installing and running a nixos-router, from the first install and the Cockpit web UI to DNS filtering, Suricata, ingress, WireGuard and working on the project itself.
nav_title: Home
code:
  - README.md
  - flake.nix
---

# nixos-router documentation

nixos-router is a NixOS module and a Cockpit web UI that turn a multi-NIC machine into a small-business router. Start with the install guide, then pick the feature you are setting up. Every guide shows the steps in the web UI, the settings they write, how the feature works on the router, and the limits to know before you rely on it.

## Where to start

New here? [Get started](start/README.md) explains how Cockpit, the settings file and NixOS generations fit together, and [Install a router](start/install.md) takes you from a bare machine to a working router.

## The guides

| Section | What it covers |
| --- | --- |
| [Get started](start/README.md) | What the router is, how to install it, the web UI, the settings file, and upgrades. |
| [Networking](network/README.md) | WAN, LAN, guest network and VLANs, and the host registry the other features build on. |
| [Access policies](access-policies/README.md) | DNS filtering policies per device, group, subnet or network; block page, directory groups and reports. |
| [Threat protection](threat-protection/README.md) | Suricata IDS and IPS: turning it on, tuning rules from events, and reading the logs. |
| [Dynamic DNS](dynamic-dns/README.md) | Cloudflare A and AAAA records for the router and your devices. |
| [Ingress](ingress/README.md) | Port forwards, the reverse proxy with Let's Encrypt certificates, and Cloudflare Tunnel. |
| [WireGuard](wireguard/README.md) | Site-to-site VPN between offices, other WireGuard peers, and remote access. |
| [Reference](reference/README.md) | Cloudflare API tokens, and every port and service on the router. |
| [Develop](develop/README.md) | Working on nixos-router itself: checks, the Cockpit plugin, settings migrations and these docs. |
