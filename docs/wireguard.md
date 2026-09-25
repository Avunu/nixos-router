---
title: WireGuard
description: Join another site's LAN to yours, or let laptops and phones reach it from anywhere, with WireGuard tunnels set up under Network → WireGuard.
code:
  - modules/network.nix
  - modules/firewall.nix
  - modules/topology.nix
  - modules/access-policies.nix
  - modules/dns-technitium.nix
  - modules/threat-protection.nix
  - modules/system.nix
  - pkgs/cockpit-router/src/network.tsx
  - pkgs/cockpit-router/src/settings.tsx
  - pkgs/cockpit-router/package.nix
---

# WireGuard

The router runs WireGuard natively. A tunnel can join another office's LAN to yours, so that devices at both sites reach each other by their own addresses. It can also let laptops and phones reach your LAN from anywhere. You set up tunnels in Cockpit under **Network → WireGuard**; the router opens the port, routes each peer's addresses into the tunnel and adds the firewall rules itself.

## Tunnels and peers

A **tunnel** is a WireGuard interface on the router, such as `wg0`. It has:

- **An address** on a small subnet that belongs to the tunnel, such as `10.100.0.1/30`.
- **A UDP listen port**, 51820 by default, which the router opens on the WAN.
- **A private key**, kept in a file on the router (`/etc/wireguard/wg0.key` by default). Peers get the matching public key.

A **peer** is the other end of the tunnel: another router, a server or a laptop. A tunnel can have several peers. Each one has:

- **A public key**, which the peer gives you.
- **An endpoint**, `host:port`, where the router can reach the peer. It's optional. Leave it empty for a peer that always connects to you, such as a laptop or a router behind NAT.
- **Allowed IPs**, the addresses that live at the peer's end.
- **A persistent keepalive**, 25 seconds by default: an empty packet sent that often to keep NAT and firewall state along the path open.

### What Allowed IPs does

Allowed IPs does two jobs at once:

- **Routing.** The router adds a route into the tunnel for every entry. Traffic for `192.168.2.0/24` leaves through the tunnel to the peer that lists it. You don't add these routes yourself.
- **Source filtering.** A packet that comes out of the tunnel is accepted only if its source address is in the sending peer's Allowed IPs. WireGuard drops anything else, and the router's reverse-path check would drop it too.

So a peer's Allowed IPs hold its own tunnel address as a `/32`, plus every subnet behind it that should reach your network. An address range can belong to only one peer of a tunnel; if two peers list the same range, only one of them gets its traffic.

:::doc-warning
Never put `0.0.0.0/0` or `::/0` in a peer's **Allowed IPs** on the router. The router would send its own default traffic into the tunnel instead of out of the WAN, cutting off its internet connection and the tunnel itself.
:::

## Site-to-site or remote access

- **Site-to-site** joins two networks. Each router lists the other site's LAN in its peer's Allowed IPs, and devices at both sites talk to each other directly. [Site-to-site VPN](/docs/wireguard/site-to-site/) walks through two nixos-routers. [Other WireGuard peers](/docs/wireguard/third-party-peer/) covers a Linux server, a cloud VM or another vendor's router.
- **Remote access** connects single devices. Each laptop or phone is a peer with one `/32` address. It reaches your LAN, and optionally the internet, through the router. See [Remote access](/docs/wireguard/remote-access/).

## What the router does for each tunnel

- **Opens the listen port** on the WAN, for UDP over IPv4 and IPv6. Nothing else about the tunnel is reachable from the internet. [Ports and services](/docs/reference/ports/) lists every open port.
- **Routes each peer's Allowed IPs** into the tunnel.
- **Forwards between the LAN and the tunnel**, in both directions.
- **Forwards from the tunnel to the internet.** Traffic that leaves by the WAN is masqueraded behind the WAN's IPv4 address, like LAN traffic. Replies come back in, but the internet can't open new connections into the tunnel.
- **Trusts the tunnel like the LAN.** Anything that comes out of the tunnel can reach every service on the router, including Cockpit, SSH and DNS. Open Cockpit by the router's LAN address, not its tunnel address; see [Open Cockpit over the tunnel](/docs/wireguard/remote-access/#open-cockpit-over-the-tunnel).
- **Counts the tunnel as an internal network.** The tunnel address and every peer's Allowed IPs join Suricata's home networks ([Threat protection](/docs/threat-protection/)), may use the router's DNS resolver, and make up the **WireGuard** network that you can assign an access policy to.

A known issue currently keeps the two forwarding items from working; see [Limits](#limits).

The router doesn't translate addresses inside the tunnel. Devices on your LAN reach the other side with their own addresses, and devices over there arrive with theirs. That's why both ends need each other's subnets in their Allowed IPs.

## Set up a tunnel

The steps are the same for every kind of peer. [Site-to-site VPN](/docs/wireguard/site-to-site/) and [Remote access](/docs/wireguard/remote-access/) give the values to use.

1. In Cockpit, open **Network → WireGuard**.
2. Type a name in the box next to **Add tunnel** (it shows `wg0` as a placeholder) and click **Add tunnel**. The name becomes the interface name: 1 to 15 letters, digits, `_`, `.` or `-`. The new tunnel is selected in the tunnel list and its settings open below.
3. Fill in the tunnel:
   - **Address (CIDR):** the router's own address on the tunnel subnet, with its prefix length, such as `10.100.0.1/30`. Use a subnet that isn't in use at either end.
   - **Listen port:** the UDP port, 51820 by default. Every tunnel needs its own port. A new tunnel always starts at 51820, so change it for the second one, for example to 51821.
   - **Private key file:** where the key is stored. It defaults to `/etc/wireguard/<name>.key`. Its help reads "Path to the private key on the router (never in the Nix store)." Keep the default.
   - **Routes:** leave it empty. Its help reads "Extra destinations routed through this tunnel.", but every peer's Allowed IPs are routed already, and WireGuard drops traffic for any address outside all peers' Allowed IPs, so an extra route has nowhere to go. The field also has no effect at the moment; see [Limits](#limits).
4. Click **Generate keypair**. The router writes a new private key to the file straight away and shows **Public key (share with peers)**. Click the copy button and keep the key: the page shows it only until you leave. See [Keys](#keys).
5. Under **Peers**, click **Add peer** and fill in the new card. Repeat for each peer.
   - **Public key:** the peer's public key.
   - **Endpoint (optional):** the peer's address or name and port, in the form `host:port`, such as `vpn.example.com:51820`. Leave it empty for a peer that only connects in. Put an IPv6 address in brackets: `[2001:db8::1]:51820`.
   - **Allowed IPs:** type a range and press Enter or click **Add**. Repeat for each range. Click the × on a range to remove it.
   - **Persistent keepalive (s):** seconds between keepalives. The default is 25, and 0 turns them off. The side behind NAT needs them.

   **Remove peer** deletes that peer.
6. Click **Save & apply**.

:::doc-warning
Click **Generate keypair** before **Save & apply**. If the private key file doesn't exist when the configuration is applied, systemd-networkd, the service that manages every network interface on the router, can't start. The apply fails, and among other things the LAN's DHCP server stops. To recover, click **Generate keypair** and then run `sudo systemctl restart systemd-networkd` on the router, or delete the tunnel and apply again.
:::

**Delete tunnel** removes the selected tunnel and its peers when you save and apply. The key file stays on the router. So does the interface, without its address or firewall rules, until the next reboot; `sudo ip link delete wg0` removes it at once.

The page doesn't check what you type. Mistakes show up as errors when you apply; see [Troubleshooting](#troubleshooting). If the page says "WireGuard is locked in the Nix configuration.", the tunnels are set in the router's Nix configuration and can only be changed there.

## In the settings file

The UI writes the `wireguard` key of `/etc/nixos/router-settings.json`, a map from tunnel name to tunnel. This is a tunnel with one peer:

```json
{
  "wireguard": {
    "wg0": {
      "address": "10.100.0.1/30",
      "listenPort": 51820,
      "privateKeyFile": "/etc/wireguard/wg0.key",
      "routes": [],
      "peers": [
        {
          "publicKey": "LTSod+XCfGvMEeoNMkXgGqGhnU5qfhDpkmxsWmrJTFU=",
          "endpoint": null,
          "allowedIPs": ["10.100.0.2/32", "192.168.2.0/24"],
          "persistentKeepalive": 25
        }
      ]
    }
  }
}
```

`address` and `privateKeyFile` are required. `listenPort` defaults to 51820, `routes` and `peers` to empty lists. In a peer, `publicKey` and `allowedIPs` are required, `endpoint` defaults to `null` and `persistentKeepalive` to 25.

## Keys

### Generate keypair

**Generate keypair** runs `wg genkey` on the router and writes the private key to the path in **Private key file** at once, before you save anything. Only root can read the file or enter its directory. The private key never leaves the router; the page shows only the public key.

It overwrites an existing key without asking. The running tunnel keeps its old key until the network service restarts: at the next reboot, or when an apply restarts it, as a change to a tunnel's port or peers does. From then on the tunnel uses the new key, and every peer that still has the old public key stops connecting. If you clicked it by mistake, copy the key the tunnel is running with back into the file:

```bash
sudo sh -c 'wg show wg0 private-key > /etc/wireguard/wg0.key'
```

### Find a public key again

The page doesn't store the public key. On the router, this prints the public key the running tunnel uses:

```bash
sudo wg show wg0 public-key
```

This one derives it from the key file:

```bash
sudo cat /etc/wireguard/wg0.key | wg pubkey
```

The `wg` command is installed once the router has at least one tunnel.

### Rotate a key

1. Click **Generate keypair** and copy the new public key.
2. At every peer, replace this router's public key with the new one, and apply there.
3. On this router, switch the running tunnel to the new key, or reboot:

   ```bash
   sudo wg set wg0 private-key /etc/wireguard/wg0.key
   ```

Peers can't connect between steps 2 and 3, so do them close together.

## Limits

:::doc-warning
**Known issue: traffic that arrives through a tunnel isn't forwarded.** The router leaves IPv4 forwarding off on its tunnels. Devices behind a peer reach the router's own services, such as Cockpit, SSH and DNS, but not the LAN or the internet, and LAN connections to them get no replies. The **Routes** field has no effect either. As a workaround, run `sudo sysctl -w net.ipv4.conf.wg0.forwarding=1` for each tunnel; it lasts until the next reboot. [Forwarding workaround](/docs/wireguard/site-to-site/#forwarding-workaround) shows how to keep it.
:::

- **No routing between tunnels, or between the peers of one tunnel.** The router forwards only between each tunnel and the LAN, and from each tunnel to the internet. Two branches can't reach each other through HQ (hub and spoke), and a laptop connected to HQ can't reach the branch. Give each pair of sites that must talk a direct tunnel of their own.
- **No NAT inside the tunnel.** The far side must route your LAN into its tunnel and list your LAN in its Allowed IPs, or replies never come back.
- **LAN subnets can't overlap.** The two ends need different LAN subnets. Renumber one side under **Network → LAN** ([Networks and VLANs](/docs/network/)).
- **The guest network is cut off.** Guest devices can't reach any tunnel, and tunnels can't reach the guest network.
- **A tunnel is as trusted as the LAN.** Every device behind a peer can reach Cockpit, SSH and DNS on the router, and every device on your LAN. SSH accepts only keys unless you've let directory administrators in with passwords, and Cockpit asks for a password, but there are no per-peer firewall rules. Connect only networks and devices you would let onto your LAN.
- **DNS isn't enforced on tunnels.** On the LAN and guest networks the router redirects DNS to its own resolver and drops DNS over TLS and IPv6 DNS ([DNS enforcement](/docs/access-policies/dns-enforcement/)). It does none of this on tunnels, so a device behind a tunnel gets an access policy only if it uses the router as its DNS server.
- **One address per tunnel, and IPv4 NAT only.** **Address (CIDR)** holds a single address, and internet traffic from a tunnel is masqueraded over IPv4 only.
- **Endpoint names are looked up once.** The router resolves a peer's endpoint name when the tunnel comes up and doesn't look it up again. If the name moves to a new address, the tunnel can stay down until you reboot or run `sudo wg set wg0 peer <public key> endpoint <host:port>` with the peer's key and endpoint.
- **No preshared keys.** Peers have no preshared-key setting. If the other side requires one, turn it off there.
- **No MTU setting.** Tunnels use WireGuard's default MTU of 1420 bytes.
- **Listen ports aren't checked for clashes.** Nothing stops two tunnels from using the same port, but only one of them can have it.
- **A listen port can't be forwarded.** The build refuses an IPv4 UDP [port forward](/docs/ingress/port-forwards/) of a tunnel's listen port.
- **Peers have no names.** Keep a note of which key and address belong to which site or device.

## Troubleshooting

When an apply fails, the log under **Apply failed.** shows the reason. These come from WireGuard settings:

- **`networking.wireguard.interfaces.wg0.ips value "10.100.0.1" requires a subnet (e.g. 192.0.2.1/32) with networkd.`** **Address (CIDR)** is empty or has no prefix length. Enter it with one, such as `10.100.0.1/30`.
- **`router: interface names (physical ports and router.wireguard tunnel names) must be 1–15 characters of letters, digits, '_', '.' or '-'; got [ wg site ].`** The tunnel name has a character outside that set, or is too long. The page can't rename a tunnel, so delete it and add it again under a valid name, such as `wg-site`.
- **`router.portForwards: forward 'wg' forwards a WireGuard listen port (UDP 51820); its DNAT would capture the tunnel's own traffic`.** A port forward uses a tunnel's listen port. Remove the forward, or give the tunnel another **Listen port**.
- **`warning: the following units failed: systemd-networkd.service`.** The private key file is missing. See the warning under [Set up a tunnel](#set-up-a-tunnel).

For a tunnel that applies cleanly but doesn't pass traffic, see [Troubleshooting](/docs/wireguard/site-to-site/#troubleshooting) on the site-to-site page.
