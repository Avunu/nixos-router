---
title: Access policies
description: DNS content filtering on the router. Named policies are assigned to groups of clients, and every client resolves through exactly one policy.
order: 3
code:
  - modules/access-policies.nix
  - modules/filter-catalog.nix
  - modules/dns-technitium.nix
  - pkgs/router-dns-tools/router_dns_tools/compile_policies.py
  - pkgs/router-dns-tools/router_dns_tools/reconcile.py
  - pkgs/cockpit-router/src/access-policies.tsx
  - pkgs/cockpit-router/src/policy-resolver.ts
---

# Access policies

Access policies are the router's DNS content filter. You build named policies, each a set of block lists, categories and allow or block rules, and assign them to groups of clients: a network, a subnet, a group of devices, or a group of people in your directory. Every client that uses the router for DNS resolves through exactly one policy.

Filtering runs in Technitium DNS Server on the router, in its Advanced Blocking app. You manage it on the **Access Policies** page in Cockpit, or in the `accessPolicies` key of the [settings file](../start/settings-file.md).

## Concepts

- **Policy:** a named set of filters. It combines [UT Capitole categories](policies.md#categories), standard ad, malware and phishing lists, your own list URLs, and per-domain allow and block rules. It also sets how a blocked query is answered. See [Build a policy](policies.md).
- **Assignment:** which clients a policy applies to. A policy can be assigned to networks (LAN, guest, WireGuard), subnets, host groups from the Hosts page, and directory groups. See [Assign policies](assignments.md).
- **Default policy:** the policy for every client no assignment matches. There is always exactly one, and it can't be deleted while it is the default.
- **Priority:** a number on each policy. It only breaks ties between policies that match a client at the same tier. Higher wins.
- **The Base policy:** when you have defined no policies, the router creates one named **Base** and makes it the default. Base blocks ads, malware and phishing with three standard filters: **AdGuard Base (ads & trackers)**, **AdGuard Malware** and **AdGuard Phishing URL Blocklist**. It answers blocked queries with a blocking address. As soon as you add a policy of your own, Base is no longer created for you. See [Your first policy replaces Base](policies.md#your-first-policy-replaces-base).

## Which policy a client gets

For each client, the router works down four tiers and stops at the first one that matches:

![The four tiers of policy resolution: host group, then directory group, then subnet or network, then the default policy. The first tier that matches decides the policy; within a tier the higher priority wins.](../images/policy-resolution.svg)

1. **Host group:** the device is registered on the Hosts page with a static IP and a group, and a policy targets that group.
2. **Directory group:** the device is registered with a static IP and a user, and a policy targets one of that user's directory groups.
3. **Subnet or network:** a policy is assigned to a subnet or network that contains the client's address. The most specific prefix wins, so a `/28` beats the `/24` it sits in.
4. **Default policy:** everything else.

The first two tiers work only for IPv4 devices with a DHCP reservation. [Assign policies](assignments.md) covers each tier, the role of priority, and the **Preview** tab that shows which policy a device would get.

> [!WARNING]
> Policies are a filter, not access control. The router identifies a device by its IPv4 address and nothing else. A device that sets another device's reserved address, or clones its MAC address to get that address from DHCP, gets that device's policy. The firewall's reverse-path check stops a guest device from claiming a LAN address, but it can't stop this within one network. Where it matters, pair a strict policy with switch-level controls such as port security or 802.1X.

## Get started

1. [Build a policy](policies.md) for each group of clients that needs different rules, and pick the default.
2. [Assign the policies](assignments.md) to networks, subnets, host groups or directory groups, then check the result on the **Preview** tab.
3. Choose **Save and apply** from the **Save** menu.
4. Optionally, turn on the [block page](block-page.md) so users see why a site is blocked and can ask for an exception.
5. Review [DNS enforcement](dns-enforcement.md) to understand which clients can and can't bypass the filter.

## How it works

1. **Settings to static policy.** When you apply a change, the build expands each policy's catalog choices (categories and standard filters) into list URLs, each tagged with its format. It writes them, together with the host registry, host group names and network ranges, to a generated file named `router-policy-static.json`.
2. **Compile and push.** `technitium-reconcile.service` merges that file with the synced directory state in `/var/lib/router-directory/directory.json`. It compiles the result into the Advanced Blocking app's configuration and pushes it through Technitium's HTTP API on `127.0.0.1`, only when it changed. The service runs after every apply that changes the router's DNS configuration.
3. **Directory changes without a rebuild.** A systemd path unit watches `directory.json`. When the directory sync rewrites it, `router-policy-push.service` recompiles and re-pushes only the Advanced Blocking configuration. See [Directory groups](directory.md).
4. **Lists and answers.** Advanced Blocking downloads every list URL itself and refreshes the lists every 24 hours. A blocked answer has a TTL of 30 seconds, so an unblocked domain starts working within half a minute once the new configuration is live.
5. **Extras in every policy.** While **Block DoH providers** is on, the router adds a list of public DNS-over-HTTPS resolver domains to every policy's block list. See [DNS enforcement](dns-enforcement.md).
6. **The router itself is not filtered.** Queries from the router's own loopback addresses use a built-in group with blocking turned off.

### How Technitium is set up

Technitium keeps its main configuration in a binary file, so the router can't generate it directly. Setup happens in three phases:

1. **First boot:** environment variables seed the configuration with the admin password from `/var/lib/router-technitium/admin.pass`, the upstream forwarders and the API port. Technitium reads them only while it has no configuration yet.
2. **App seeding:** before the DNS server starts, the router copies the DNS apps into `/var/lib/technitium-dns-server/apps/`. The apps are Advanced Blocking, Log Exporter, Block Page and the router's own Router Live DNS app, all built from source with the router. Filtering is therefore active from the first second. The Block Page app also gets the branded page generated from your settings.
3. **Reconcile:** `technitium-reconcile.service` sets the server settings and the router's own zone. It also creates the [split-horizon](dns-enforcement.md#split-horizon-dns) and SafeSearch zones, sets each app's configuration (including the compiled policies), and creates the read-only API token the Cockpit dashboards use. It is idempotent and retries on failure.

The router builds Technitium from source without its web console, so there is nothing to open in a browser. The API that the router and Cockpit manage it through listens on `127.0.0.1` only, port 5380 by default. [Troubleshooting](troubleshooting.md#inspect-technitium) shows how to query it.

Setting `dns.technitium.enable` to `false` turns off filtering, not DNS. See [When Technitium is off](dns-enforcement.md#when-technitium-is-off).

## In this section

- [Build a policy](policies.md): the policy editor, section by section.
- [Assign policies](assignments.md): networks, subnets, host groups and directory groups, precedence, and the **Preview** tab.
- [Block page and exceptions](block-page.md): the page blocked users see, and approving their exception requests.
- [DNS enforcement](dns-enforcement.md): how the router keeps clients on its resolver, SafeSearch, and split-horizon DNS.
- [Directory groups](directory.md): connecting LDAP or Active Directory so policies follow people.
- [Reports](reports.md): dashboards, the query log and scheduled PDF reports.
- [Troubleshooting](troubleshooting.md): symptoms, causes and fixes.
