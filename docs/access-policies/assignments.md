---
title: Assign policies
description: Assign access policies to networks, subnets, host groups and directory groups, understand precedence and priority, and preview the result.
code:
  - modules/access-policies.nix
  - modules/hosts.nix
  - modules/topology.nix
  - pkgs/router-dns-tools/router_dns_tools/compile_policies.py
  - pkgs/cockpit-router/src/access-policies.tsx
  - pkgs/cockpit-router/src/policy-resolver.ts
---

# Assign policies

Assignments decide which clients a policy applies to. A policy can be assigned to whole networks, to subnets, to groups of registered devices, and to directory groups of people. This page explains each kind, how the router picks one policy when several match, and how to check the result on the **Preview** tab before you apply.

## Before you start

- The host group and directory group tiers apply only to devices registered on the Hosts page **with a Static IP**, which is a DHCP reservation. See [Hosts and host groups](/docs/network/hosts/).
- Directory groups need a directory connection. See [Directory groups](/docs/access-policies/directory/).
- A **Guest** assignment needs the guest network turned on. See [Networks and VLANs](/docs/network/).

## Assignment types

Assignments are the last section of the policy editor on **Access Policies → Policies**. A policy can use any mix of them.

| Field | JSON key | Matches | Tier |
| --- | --- | --- | --- |
| **Networks** | `networks` | Every address in the chosen networks: **LAN**, **Guest** or **WireGuard** | Subnet or network |
| **Subnets (CIDR)** | `subnets` | Every address in the listed ranges, such as `192.168.1.128/25` | Subnet or network |
| **Host groups** | `hostGroups` | Registered devices whose **Group** on the Hosts page is one of these | Host group |
| **Directory groups** | `directoryGroups` | Registered devices whose **User** belongs to one of these directory groups | Directory group |

Notes on each field:

- **Networks:** **LAN** and **Guest** cover the network's subnet. **WireGuard** covers each tunnel's own address range plus every peer's allowed IPs, which includes the remote LAN of a site-to-site peer. While the guest network is off, the **Guest** checkbox is disabled with the tooltip "The guest network is not enabled (Network page)."
- **Subnets (CIDR):** type a range and add it to the list. The build doesn't check these entries, so enter valid CIDR notation.
- **Host groups:** a checklist of the groups defined on **Hosts → Groups**. It shows "No groups defined" until you create one.
- **Directory groups:** type the group name exactly as the directory spells it. The list autocompletes only groups the router has already looked up, so a new group needs the **Use "*name*"** option. A name the last directory sync couldn't resolve shows as an orange chip with the tooltip "The last directory sync could not resolve this group name." Matching is case-insensitive.

## How the winning policy is chosen

For each client, the router checks four tiers in order and stops at the first match. The [diagram on the overview page](/docs/access-policies/#which-policy-a-client-gets) shows the same order. The Policies tab summarizes it as: "One policy wins per client: host group, then directory group, then subnet/network, then the default policy; within a tier the highest priority wins."

### Tier 1: host group

The device is on the Hosts page with a **Static IP** and a **Group**, and at least one policy lists that group under **Host groups**. A device belongs to one group at most. If several policies target that group, the one with the highest priority wins. If no policy targets the group, the router moves on to tier 2.

### Tier 2: directory group

The device is on the Hosts page with a **Static IP** and a **User**, the directory sync has resolved that user, and at least one policy lists one of the user's groups under **Directory groups**. A user's groups include their primary group, so a policy for Active Directory's `Domain Users` works. If the user belongs to several targeted groups, the policy with the highest priority wins.

### Tier 3: subnet or network

The client's address falls inside a range from **Networks** or **Subnets (CIDR)**. Networks and subnets form one tier, and the most specific range wins regardless of priority. A policy on `192.168.1.128/25` beats a policy on the LAN (`192.168.1.0/24`) for the addresses in that half. Priority matters only when two policies claim exactly the same range, for example when both are assigned to **LAN**.

This tier also covers devices that are registered without a static IP or not registered at all, matched by the address DHCP gave them, and reserved devices whose group and user matched no policy.

### Tier 4: default policy

Every client that matched nothing above gets the default policy.

### Priority

**Priority** only breaks ties inside one tier:

- two policies target the same host group;
- a user belongs to two directory groups that different policies target;
- two policies are assigned the same network or the same subnet.

It never lifts a policy into a higher tier, and it never beats a more specific subnet. If tied policies also have equal priority, which one wins isn't defined, so give competing policies different priorities.

### Examples

These use the [school example](/docs/access-policies/policies/#worked-example-a-school): `Students` is the default policy, has priority 0 and targets the `Library kiosks` host group and the `Students` directory group. `Staff` has priority 10 and targets the `Staff` directory group.

| Client | Result | Why |
| --- | --- | --- |
| Laptop with a static IP, **User** `jdoe`, member of `Staff` | Staff | Tier 2 match |
| Same laptop, also in host group `Library kiosks`, targeted by Students | Students | Tier 1 beats tier 2 |
| User in both `Students` and `Staff` groups | Staff | Both match tier 2; priority 10 beats 0 |
| Phone with no reservation | Students | No device tier applies; default policy |
| Laptop with **User** `jdoe` but no static IP | Students | Device tiers need a reservation |

## Preview a client

The **Preview** tab shows which policy a client would get, and why. It reads the saved settings file, so click **Save** first; you don't need to apply.

1. Open **Access Policies → Preview**.
2. Under **Look up by**, choose one of:
   - **Registered device**, then pick it under **Device**;
   - **IP address**, then type it under **IP address**. If a registered device reserves that address, the preview treats it as that device.
   - **Directory user**, then type the login name under **User**, such as `jdoe`. Names the router has already resolved autocomplete. If the last sync couldn't resolve the name, the page says "The last directory sync could not resolve this name — the user tier will not match."
3. Read the **Resolution chain** card. Each row is a tier the router checked, with **#**, **Tier**, **Detail** and **Policy** columns. The row that decided the result is highlighted and labeled **winner**. The last line reads, for example, `Client would get policy "Staff".`

Details you may see:

- `device 'Lab PC 01' in group 'Library kiosks'`: the host group tier matched.
- `device 'Lab PC 01' has group 'Library kiosks' but NO static IP — tier skipped`: the device needs a reservation.
- `user 'jdoe' (4 directory group memberships)`: the directory tier ran, and the user belongs to four groups.
- `matched via subnet 192.168.1.128/25` or `matched via network lan (192.168.1.0/24)`: tier 3 matched.
- `no network/subnet assignment matches 192.168.1.50`: tier 3 found nothing, so the default applies.

The **Users** page shows the same calculation in its **Effective policy** column for each directory user and each of their devices.

## In the settings file

Assignments live in each policy's `assignments` object. Host groups and devices are separate top-level keys, managed on the Hosts page:

```json
{
  "hostGroups": [
    { "name": "Library kiosks", "description": "Shared computers in the library" }
  ],
  "hosts": [
    { "mac": "3c:22:fb:12:34:56", "name": "Lab PC 01", "network": "lan", "staticIp": "192.168.1.101", "group": "Library kiosks" },
    { "mac": "a4:83:e7:65:43:21", "name": "jdoe laptop", "network": "lan", "staticIp": "192.168.1.120", "user": "jdoe" }
  ],
  "accessPolicies": {
    "defaultPolicy": "Students",
    "policies": [
      {
        "name": "Students",
        "assignments": {
          "networks": [],
          "subnets": ["192.168.1.128/25"],
          "hostGroups": ["Library kiosks"],
          "directoryGroups": ["Students"]
        }
      },
      {
        "name": "Staff",
        "priority": 10,
        "assignments": {
          "networks": ["wireguard"],
          "directoryGroups": ["Staff"]
        }
      }
    ]
  }
}
```

## Limits

- **Device tiers are IPv4 only.** The host group and directory group tiers are anchored to each device's IPv4 DHCP reservation. The router drops DNS over IPv6 on the LAN and guest networks and doesn't advertise an IPv6 resolver, so clients there use IPv4. An IPv6 query that reaches the router anyway, for example over WireGuard, can't match a device tier.
- **A reservation is required.** A device with a **Group** or **User** but no **Static IP** follows its network's policy. The Hosts page warns "No static IP — device-tier policies cannot apply", and the build warns: `router.hosts: device 'jdoe laptop' has a group or user assignment but no static IP — device-tier access policies cannot apply to it (it follows its network's default policy).`
- **WireGuard clients are filtered only if they use the router for DNS.** The router doesn't redirect DNS arriving over WireGuard. A peer gets a policy only when its configuration names the router as its DNS server. WireGuard peers can't be registered on the Hosts page, so they get network or subnet policies only. To give one peer its own policy, assign its tunnel address as a `/32` subnet. See [DNS enforcement](/docs/access-policies/dns-enforcement/#what-the-router-does-not-enforce).
- **The address is the identity.** A device that takes another device's address gets its policy. See the warning on [Access policies](/docs/access-policies/#which-policy-a-client-gets).

## Build errors

The apply fails, and the router keeps running its current configuration, when assignments don't add up:

| Message | Fix |
| --- | --- |
| `router.accessPolicies: duplicate policy name(s)` | Give every policy a unique name. The Policies tab flags this as "Another policy already has this name." |
| `router.accessPolicies.defaultPolicy 'Base' is not a defined policy (have: Students, Staff)` | The default names a policy that doesn't exist, usually after you added your first policy or deleted a policy in the settings file. Turn on **Default policy** on an existing policy. |
| `router.accessPolicies: policy 'Students' references undefined host group(s): Library kiosks` | Create the group on **Hosts → Groups**, or remove it from the policy. |
| `router.accessPolicies: policy 'Guests' is assigned to the guest network, but router.guest.enable is false` | Turn on the guest network, or clear the policy's **Guest** checkbox. |

A directory group that doesn't exist isn't a build error. It shows up as an unresolved name after the next directory sync. See [Directory groups](/docs/access-policies/directory/#names-are-looked-up-on-demand).
