---
title: Other WireGuard peers
description: Connect the router's LAN to a WireGuard endpoint that isn't a nixos-router, such as a Linux gateway with wg-quick, a cloud VM or another vendor's router.
code:
  - modules/network.nix
  - modules/firewall.nix
  - pkgs/cockpit-router/src/network.tsx
---

# Other WireGuard peers

The router speaks standard WireGuard, so the far end of a site-to-site tunnel doesn't have to be another nixos-router. It can be a Linux machine running wg-quick, a cloud VM or another vendor's router. This page covers what that far end must do, gives a wg-quick configuration for a Linux site gateway, and shows the matching entry on the router. The steps on the router are the same as in [Site-to-site VPN](/docs/wireguard/site-to-site/).

## The example

- **The router (HQ):** LAN `192.168.1.0/24`, reachable as `hq.example.com`, tunnel `wg0` with address `10.100.2.1/30` on UDP port 51820.
- **The far side:** a Linux gateway for a warehouse LAN, `192.168.3.0/24`, behind NAT. Its tunnel address is `10.100.2.2/30`, and it dials the router.

If the router already has a tunnel called `wg0` on port 51820, use another name and port for this one, such as `wg1` and 51821.

## What the far side must do

The router doesn't translate addresses inside the tunnel. Your LAN devices arrive at the far side with their own `192.168.1.x` addresses, and the router expects the far side's devices to arrive with theirs. So the far side must:

- **Accept your LAN.** Its peer entry for the router lists your tunnel address and your LAN in AllowedIPs: `10.100.2.1/32` and `192.168.1.0/24`. Otherwise it drops everything your LAN sends.
- **Route your LAN into its tunnel.** wg-quick adds a route for every AllowedIPs entry by itself. Other products may need a static route to `192.168.1.0/24` through the WireGuard interface.
- **Forward between its LAN and the tunnel.** IP forwarding must be on, and its firewall must allow traffic between the WireGuard interface and its LAN.
- **Get replies back to the gateway.** If the gateway isn't its LAN's default router, that LAN's router needs a static route: `192.168.1.0/24` via the gateway's LAN address.
- **Route rather than NAT.** If the far side masquerades its LAN into the tunnel, connections still work, since everything then arrives from its tunnel address, which is in the router's Allowed IPs for it. But the router sees every device over there as one address, so logs, [threat protection](/docs/threat-protection/) events and access policies can't tell them apart.

## A wg-quick gateway

On the Linux gateway, install the WireGuard tools and create a key pair:

```bash
sudo sh -c 'install -d -m 700 /etc/wireguard && umask 077 && wg genkey > /etc/wireguard/wg0.key'
sudo cat /etc/wireguard/wg0.key | wg pubkey
```

The second command prints the gateway's public key, which goes into the router. Then write `/etc/wireguard/wg0.conf`, pasting the private key from `/etc/wireguard/wg0.key` and the router's public key from **Public key (share with peers)**:

```ini
[Interface]
Address = 10.100.2.2/30
PrivateKey = <the gateway's private key>
ListenPort = 51820

[Peer]
# The nixos-router at HQ
PublicKey = XoJpYi5jIthUueiJG/ofsGU2Ec1DZX8Hpi6w6mg20g0=
Endpoint = hq.example.com:51820
AllowedIPs = 10.100.2.1/32, 192.168.1.0/24
PersistentKeepalive = 25
```

`PersistentKeepalive` keeps the gateway's NAT mapping open, so the router can reach the warehouse at any time.

Turn on IP forwarding, now and at boot, and start the tunnel:

```bash
echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/99-wireguard-forward.conf
sudo sysctl --system
sudo systemctl enable --now wg-quick@wg0
```

If the gateway runs a firewall, allow forwarding between `wg0` and its LAN interface.

## The matching entry on the router

On the router, open **Network → WireGuard** and set up the tunnel as in [Set up a tunnel](/docs/wireguard/#set-up-a-tunnel):

1. Add the tunnel `wg0` with **Address (CIDR)** `10.100.2.1/30` and **Listen port** 51820.
2. Click **Generate keypair** and copy the public key for the gateway's `[Peer]` section.
3. Add a peer:
   - **Public key:** the gateway's public key.
   - **Endpoint (optional):** empty, since the gateway dials in.
   - **Allowed IPs:** `10.100.2.2/32` and `192.168.3.0/24`.
   - **Persistent keepalive (s):** 25.
4. Click **Save & apply**.

In `/etc/nixos/router-settings.json`:

```json
{
  "wireguard": {
    "wg0": {
      "address": "10.100.2.1/30",
      "listenPort": 51820,
      "privateKeyFile": "/etc/wireguard/wg0.key",
      "routes": [],
      "peers": [
        {
          "publicKey": "aF2eDbuLsncPWiZXdKpov+io0uWyEwW3XdngbGuePwE=",
          "endpoint": null,
          "allowedIPs": ["10.100.2.2/32", "192.168.3.0/24"],
          "persistentKeepalive": 25
        }
      ]
    }
  }
}
```

### When the router dials out

If the far side has the fixed public address, such as a cloud VM at `vpn.example.net`, reverse the roles. On the router, set the peer's **Endpoint (optional)** to `vpn.example.net:51820` and keep the keepalive at 25. On the far side, drop the `Endpoint` and `PersistentKeepalive` lines, and open its UDP listen port in its own firewall or cloud security group. The router's LAN is still in the far side's AllowedIPs either way.

## Interoperability notes

- **Keys are the same everywhere.** WireGuard keys are 32-byte Curve25519 keys in base64, whatever made them. Paste them as they are.
- **No preshared key.** The router has no preshared-key setting. A preshared key must match on both ends, so leave it off on the far side.
- **MTU.** The router sets no MTU, so its tunnels use WireGuard's default of 1420 bytes. wg-quick picks its own from the route to the endpoint. If large transfers stall while pings work, lower the far side's MTU with `MTU = 1380` in its `[Interface]` section; the router has no equivalent setting.
- **The far side's firewall.** The side that gets dialed must allow its UDP listen port in from the internet. The far side must also allow forwarding from the tunnel to its LAN, which some products block by default.
- **Other vendors' names.** Router products label the same settings differently: AllowedIPs may appear as allowed IPs, remote subnets or networks, and some also need a separate static route or a firewall rule for the WireGuard interface.
- **IPv6 endpoints** go in brackets: `[2001:db8::10]:51820`.
- **No internet through the far side.** Don't put `0.0.0.0/0` in the router's Allowed IPs for the peer to send your internet traffic through it; the router would lose its own connection. See [What Allowed IPs does](/docs/wireguard/#what-allowed-ips-does).

For checking the tunnel and fixing problems, see [Check the tunnel](/docs/wireguard/site-to-site/#check-the-tunnel) and [Troubleshooting](/docs/wireguard/site-to-site/#troubleshooting) on the site-to-site page. On the Linux gateway, `sudo wg show` gives the same view.
