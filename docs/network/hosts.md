---
title: Hosts and host groups
description: Register devices on the Hosts page, give them static IPs, IPv6 suffixes and public names, and group them for access policies.
code:
  - modules/hosts.nix
  - modules/network.nix
  - modules/dns-technitium.nix
  - modules/access-policies.nix
  - pkgs/cockpit-router/src/hosts.tsx
  - pkgs/cockpit-router/src/hosts-live.ts
  - pkgs/cockpit-router/src/ip-math.ts
  - pkgs/cockpit-router/src/ingress.ts
  - pkgs/cockpit-router/src/reverse-proxy.tsx
---

# Hosts and host groups

The host registry is the router's list of known devices, keyed by MAC address. Registering a device lets you give it a fixed address, a DNS name, a public name and a group. Access policies, port forwards, the reverse proxy, the Cloudflare Tunnel and dynamic DNS all refer to devices by their registered name, so most setups start here.

You manage the registry on the **Hosts** page, which has two tabs: **Devices** and **Groups**.

## The Devices tab

The table merges two lists: the devices registered in the settings, and the devices the router sees on its networks right now, read from its neighbor table every 15 seconds.

| Column | Shows |
| --- | --- |
| **Status** | **online** for a registered device that is on the network, **new** for one that is on the network but not registered, **offline** for a registered device that isn't seen. |
| **Name** | The registered name, or in italics the name the device announces over mDNS. |
| **IP(s)** | The static IP and IPv6 suffix in bold, then the addresses the device uses now. A warning icon means the device has a group or user but no static IP. |
| **Vendor** | The manufacturer, looked up from the MAC address in nmap's vendor database. |
| **Group**, **User**, **MAC address** | From the registry. |

Use the filter box to search by name, IP, MAC, vendor, group or user. Turn off **Show unregistered** to hide the **new** devices, and press **Refresh** to reload the neighbor table at once.

### Register a device

1. Find the device in the table. It shows as **new**.
2. Click **Adopt**. The editor opens as "Adopt device" with the MAC address, and pre-fills the name the device announces, its network, and a suggested static IP.
3. Fill in the fields described below, then click **Adopt**.
4. Press **Save & apply**.

To change a registered device, click **Edit**, change the fields, click **Update**, then **Save & apply**.

A device that isn't online yet can't be adopted from the table. Add it to the settings file instead; see [In the settings file](#in-the-settings-file).

## Device fields

| Field | Setting | What it does |
| --- | --- | --- |
| **Name** | `name` | Required and unique. Letters, digits, spaces, dots, dashes and underscores, starting with a letter or digit. Other features refer to the device by this name. |
| **Network** | `network` | `lan` (the default) or `guest`: the network that owns the device's lease. **Guest** is offered only while the guest network is on. |
| **Static IP** | `staticIp` | A DHCP reservation. Leave it empty for a dynamic lease. **Suggest** proposes an address. |
| **IPv6 suffix** | `ipv6Suffix` | The low 64 bits of the device's IPv6 address, such as `::10`. **EUI-64** fills it in from the MAC address. |
| **Public hostname** | `publicHostname` | A public DNS name, such as `nas.example.com`, that dynamic DNS keeps pointed at the device. |
| **Group** | `group` | A device group from the **Groups** tab. |
| **User** | `user` | The directory user the device belongs to, as `id <name>` resolves it on the router. See [Directory groups](/docs/access-policies/directory/). |
| **Notes** | `notes` | Free text for you. |

The MAC address identifies the device and can't be edited. To change it, remove the device and adopt it again.

### Static IP

A static IP is a DHCP reservation: the router always hands this address to the device's MAC address. The address must lie in the network's subnet and can't be the gateway or another device's reservation. An address inside the dynamic pool is allowed, with the warning "Inside the dynamic pool — will be excluded from dynamic assignment."

**Suggest** keeps the device's current address if it lies outside the pool. Otherwise it picks the first free address between the gateway and the start of the pool, such as `192.168.1.2`.

A static IP is what most other features need:

- **Access policies.** Policies tell devices apart by IPv4 address, so a device's group and user only take effect with a static IP. Without one, the device gets its network's policy, and the editor warns "No static IP — device-tier policies cannot apply". See [Assign policies](/docs/access-policies/assignments/).
- **Port forwards.** An IPv4 forward sends traffic to the device's static IP. See [Port forwards](/docs/ingress/port-forwards/).
- **Reverse proxy and Cloudflare Tunnel.** Both forward requests to the device's static IP. See [Reverse proxy](/docs/ingress/reverse-proxy/) and [Cloudflare Tunnel](/docs/ingress/cloudflare-tunnel/).
- **Local DNS.** While **Publish static hosts** is on (the default, on **DNS → Resolver**), the router publishes the device as `<name>.<lan.domain>`, such as `nas.lan`, with a reverse (PTR) record. Names are lowercased, and characters that DNS doesn't allow become dashes, so `Kiosk 1` becomes `kiosk-1.lan`. Registered devices without a static IP get the same name, resolved live from the address they use at the moment. Two devices whose names turn into the same DNS name both go without one.

### IPv6 suffix

Your provider delegates the IPv6 prefix, and it can change at any time. So the router identifies a device by the low 64 bits of its address, its interface identifier, and combines that with whatever prefix is current. The suffix is what IPv6 port forwards and the device's AAAA record use.

The suffix must stay the same when the prefix changes, so pick one of these:

- **A token set on the device.** On Linux use `ip token set ::10 dev eth0`, networkd's `Token=::10`, or NetworkManager's `ipv6.token`. This is the most predictable option.
- **The device's EUI-64 identifier.** Use this only if the device really builds its address from its MAC. The **EUI-64** button fills it in.

Don't use a privacy or temporary address, or an RFC 7217 "stable-privacy" address, which is the default on most desktops and phones. They change whenever the prefix changes, so the forward and the AAAA record would stop matching. Under the field, "In use now:" lists the global suffixes the device is using, as a convenience; pick one only if you know it is stable.

### Public hostname

A public hostname is a name that [Dynamic DNS](/docs/dynamic-dns/) publishes for the device: an A record for the router's WAN IPv4 address, which reaches the device through a port forward, and an AAAA record for the device's own IPv6 address when it has a suffix. When the device has a static IP, LAN clients that look the name up get that address instead, because port forwards have no NAT loopback.

The name must be a valid DNS name and unique across devices and the router's own dynamic DNS names.

### The fields that matter for publishing a device

| Field | Needed for |
| --- | --- |
| `staticIp` | IPv4 port forwards, as the forward's target; the reverse proxy; the Cloudflare Tunnel; device-tier access policies. |
| `ipv6Suffix` | IPv6 port forwards, and the device's AAAA record. |
| `publicHostname` | A DNS name that dynamic DNS publishes for the device. |

## Rename or remove a device

Port forwards, reverse proxy routes and tunnel hostnames refer to a device by name, so the Hosts page keeps them in step:

- **Rename** a device, and its forwards, routes and tunnel hostnames follow the new name in the same save.
- **Remove** a device, and they are removed with it. The confirmation says what goes, for example **Confirm remove (and its 2 port forward(s), 1 proxy route(s))**.

## The Groups tab

A host group is a named set of devices, such as "Kiosks" or "Staff laptops". Its purpose is access policies: a policy assigned to a host group applies to every device in it, and host groups win over every other kind of assignment. See [Assign policies](/docs/access-policies/assignments/).

- **Add a group:** enter a **Group name** and an optional description, then click **Add group**. Names must be unique, start with a letter or digit, and contain only letters, digits, spaces, dashes and underscores.
- **Add devices to it** with the **Group** field in each device's editor. The **Members** column counts them.
- **Rename** a group, and its member devices follow.
- **Delete** a group, and its members are left without one. The confirmation says how many devices lose it.

Press **Save & apply** afterwards.

:::doc-warning
Renaming or deleting a group does not update the access policies that name it. The next build then fails with `router.accessPolicies: policy 'Kiosk' references undefined host group(s): Kiosks`. Change the policy's assignment on **Access Policies** first, or in the same save.
:::

## In the settings file

```json
{
  "hostGroups": [
    { "name": "Servers", "description": "Always-on machines" },
    { "name": "Kiosks", "description": "Library catalog terminals" }
  ],
  "hosts": [
    {
      "mac": "aa:bb:cc:dd:ee:01",
      "name": "nas",
      "network": "lan",
      "staticIp": "192.168.1.10",
      "ipv6Suffix": "::10",
      "publicHostname": "nas.example.com",
      "group": "Servers",
      "user": null,
      "notes": "Synology in the server closet"
    },
    {
      "mac": "aa:bb:cc:dd:ee:02",
      "name": "Kiosk 1",
      "network": "lan",
      "staticIp": "192.168.1.21",
      "group": "Kiosks"
    }
  ]
}
```

Only `mac` and `name` are required. MAC addresses use colons.

## Helpers elsewhere

- **Port scan.** In the reverse proxy's route form, once you pick a device with a static IP, **Scan ports** under **Port** checks that address for open ports among the 100 most common, with nmap. Click a port in the result to use it. See [Reverse proxy](/docs/ingress/reverse-proxy/).

## Limits

- Devices are identified by MAC address on the network, and by IPv4 address for policies. A device that clones another's MAC address or takes its reserved address gets its policy. See [Access policies](/docs/access-policies/).
- Only LAN and guest devices can be registered. WireGuard peers are not hosts.
- The vendor column only knows MAC prefixes in nmap's database. A device that uses a randomized (private) MAC address shows no vendor, and shows up as a new device whenever that address changes.

## Troubleshooting

The editor checks each field as you type and won't save an invalid one. The build checks the same rules:

| Build message | Fix |
| --- | --- |
| `router.hosts: duplicate MAC address(es): aa:bb:cc:dd:ee:01` | Two entries share a MAC address. Remove one. |
| `router.hosts: duplicate device name(s): nas` | Rename one of the devices. |
| `router.hosts: duplicate static IP(s): 192.168.1.10` | Give each device its own address. |
| `router.hosts: device 'nas' static IP 192.168.2.10 is outside the lan subnet 192.168.1.0/24` | Use an address in the device's network. |
| `router.hosts: device 'nas' static IP collides with the lan gateway 192.168.1.1` | Pick another address. |
| `router.hosts: device 'nas' is on the guest network, but router.guest.enable is false` | Turn on the guest network, or move the device to the LAN. |
| `router.hosts: device 'nas' references undefined group 'Servers'` | Create the group, or clear the device's group. |
| `router.hosts: device 'nas' IPv6 suffix '2001:db8::10' is not an interface identifier — ...` | Enter only the low 64 bits, such as `::10`. |
| `router.hosts: duplicate IPv6 suffix(es) on one network: lan/::10` | Give each device on a network its own suffix. |
| `router.hosts: device 'nas' public hostname 'nas' is not a valid DNS name (e.g. nas.example.com)` | Use a full DNS name. |
