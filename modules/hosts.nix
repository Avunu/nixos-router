# ── Hosts module ───────────────────────────────────────────────────────────────
# Persistent device registry and device groups:
#   • router.hosts       — MAC-keyed inventory of known devices. A host with a
#                          `staticIp` gets a DHCP reservation (rendered as a
#                          [DHCPServerStaticLease] section by network.nix), which
#                          pins the IP the access-policy compiler maps to a
#                          filtering group. Hosts may reference a device group
#                          and/or a directory user for policy assignment.
#   • router.hostGroups  — named device groups (e.g. "Lab", "Kiosks") that
#                          access policies can target via assignments.hostGroups.
#
# Devices without a static IP fall back to their network's default policy —
# device-tier and user-tier policies require a pinned address (warned below).
#
# Two optional fields make a host reachable from the internet:
#   • ipv6Suffix     — the host's IPv6 interface identifier. The delegated
#                      prefix is dynamic, so the host is identified by the low
#                      64 bits alone; firewall.nix matches on them for IPv6
#                      port-forward pinholes and ddns.nix combines them with the
#                      live prefix for the host's AAAA record.
#   • publicHostname — a public DNS name router.ddns keeps pointed at the host
#                      (A = WAN IPv4, AAAA = delegated prefix + ipv6Suffix).
{
  config,
  lib,
  ...
}:
with lib;
let
  cfg = config.router;
  netLib = import ./lib/net.nix { inherit lib; };

  # ── IPv4 helpers ─────────────────────────────────────────
  # Minimal pure-Nix IPv4 arithmetic for subnet-containment assertions.
  ipToInt =
    ip:
    let
      parts = map toInt (splitString "." ip);
    in
    foldl' (acc: o: acc * 256 + o) 0 parts;

  # True when `ip` lies inside `network`/`prefix` (IPv4 only).
  inSubnet =
    ip: network: prefix:
    let
      shift = 32 - prefix;
      # Right-shift by dividing through 2^shift — Nix ints are 64-bit signed,
      # safe for 32-bit addresses.
      block = n: n / (pow 2 shift);
      pow = base: e: if e == 0 then 1 else base * pow base (e - 1);
    in
    block (ipToInt ip) == block (ipToInt network);

  networkOf =
    net:
    if net == "lan" then
      {
        base = cfg.lan.networkAddress;
        prefix = cfg.lan.prefixLength;
        gateway = cfg.lan.address;
      }
    else
      {
        base = cfg.guest.networkAddress;
        prefix = cfg.guest.prefixLength;
        gateway = cfg.guest.address;
      };

  groupNames = map (g: g.name) cfg.hostGroups;
  staticHosts = filter (h: h.staticIp != null) cfg.hosts;
  suffixHosts = filter (h: h.ipv6Suffix != null) cfg.hosts;
  publicNames = map (h: toLower h.publicHostname) (filter (h: h.publicHostname != null) cfg.hosts);

  # Suffixes are compared normalized ("::0042" == "::42") and per network:
  # the same interface ID on LAN and guest names two different addresses.
  suffixKeys = map (h: "${h.network}/${toString (netLib.parseSuffix h.ipv6Suffix)}") (
    filter (h: netLib.parseSuffix h.ipv6Suffix != null) suffixHosts
  );

  dupsOf =
    xs:
    attrNames (
      filterAttrs (_: c: c > 1) (foldl' (acc: x: acc // { ${x} = (acc.${x} or 0) + 1; }) { } xs)
    );
in
{
  options.router = {
    hosts = mkOption {
      type = types.listOf (
        types.submodule {
          options = {
            mac = mkOption {
              type = types.strMatching "([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}";
              description = "Device MAC address (colon-separated).";
            };
            name = mkOption {
              type = types.strMatching "[A-Za-z0-9][A-Za-z0-9_. -]*";
              description = "Human-readable device name (unique).";
            };
            staticIp = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = ''
                DHCP reservation for this device. Required for device-tier or
                user-tier access policies (IP→group mapping must be stable).
                Must lie inside the declared network's subnet.
              '';
            };
            network = mkOption {
              type = types.enum [
                "lan"
                "guest"
              ];
              default = "lan";
              description = "Network segment that owns this device's lease.";
            };
            group = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = "Device group (router.hostGroups name) for policy assignment.";
            };
            user = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = "Directory user (id or email) this device belongs to.";
            };
            ipv6Suffix = mkOption {
              type = types.nullOr types.str;
              default = null;
              example = "::42";
              description = ''
                IPv6 interface identifier (the low 64 bits) this device uses on
                its network, e.g. `::42` for a token configured on the device, or
                its EUI-64 identifier. The ISP-delegated prefix is dynamic, so the
                device is identified by this suffix alone. Required for IPv6 port
                forwards and for an AAAA record on `publicHostname`. Use a stable
                identifier: RFC 7217 "stable-privacy" and temporary addresses
                change when the prefix does.
              '';
            };
            publicHostname = mkOption {
              type = types.nullOr types.str;
              default = null;
              example = "nas.example.com";
              description = ''
                Public DNS name kept up to date by router.ddns: an A record for
                the WAN IPv4 address (reach the device through a port forward)
                and, when `ipv6Suffix` is set, an AAAA record for the device's
                own global IPv6 address.
              '';
            };
            notes = mkOption {
              type = types.str;
              default = "";
              description = "Free-form administrator notes.";
            };
          };
        }
      );
      default = [ ];
      description = "Persistent device registry (managed via the Cockpit Hosts page).";
    };

    hostGroups = mkOption {
      type = types.listOf (
        types.submodule {
          options = {
            name = mkOption {
              type = types.strMatching "[A-Za-z0-9][A-Za-z0-9_ -]*";
              description = "Group name (unique; referenced by hosts and access policies).";
            };
            description = mkOption {
              type = types.str;
              default = "";
              description = "Free-form group description.";
            };
          };
        }
      );
      default = [ ];
      description = "Named device groups that access policies can target.";
    };
  };

  config = {
    assertions = [
      {
        assertion = dupsOf (map (h: toLower h.mac) cfg.hosts) == [ ];
        message = "router.hosts: duplicate MAC address(es): ${
          concatStringsSep ", " (dupsOf (map (h: toLower h.mac) cfg.hosts))
        }";
      }
      {
        assertion = dupsOf (map (h: h.name) cfg.hosts) == [ ];
        message = "router.hosts: duplicate device name(s): ${
          concatStringsSep ", " (dupsOf (map (h: h.name) cfg.hosts))
        }";
      }
      {
        assertion = dupsOf (map (h: h.staticIp) staticHosts) == [ ];
        message = "router.hosts: duplicate static IP(s): ${
          concatStringsSep ", " (dupsOf (map (h: h.staticIp) staticHosts))
        }";
      }
      {
        assertion = dupsOf groupNames == [ ];
        message = "router.hostGroups: duplicate group name(s): ${concatStringsSep ", " (dupsOf groupNames)}";
      }
      {
        assertion = dupsOf suffixKeys == [ ];
        message = "router.hosts: duplicate IPv6 suffix(es) on one network: ${concatStringsSep ", " (dupsOf suffixKeys)}";
      }
      {
        assertion = dupsOf publicNames == [ ];
        message = "router.hosts: duplicate public hostname(s): ${concatStringsSep ", " (dupsOf publicNames)}";
      }
    ]
    # Per-host referential and subnet checks.
    ++ concatMap (
      h:
      let
        net = networkOf h.network;
      in
      [
        {
          assertion = h.group == null || elem h.group groupNames;
          message = "router.hosts: device '${h.name}' references undefined group '${toString h.group}'";
        }
        {
          assertion = h.network != "guest" || cfg.guest.enable;
          message = "router.hosts: device '${h.name}' is on the guest network, but router.guest.enable is false";
        }
        {
          assertion = h.staticIp == null || inSubnet h.staticIp net.base net.prefix;
          message = "router.hosts: device '${h.name}' static IP ${toString h.staticIp} is outside the ${h.network} subnet ${net.base}/${toString net.prefix}";
        }
        {
          assertion = h.staticIp == null || h.staticIp != net.gateway;
          message = "router.hosts: device '${h.name}' static IP collides with the ${h.network} gateway ${net.gateway}";
        }
        {
          assertion = h.ipv6Suffix == null || netLib.parseSuffix h.ipv6Suffix != null;
          message = "router.hosts: device '${h.name}' IPv6 suffix '${toString h.ipv6Suffix}' is not an interface identifier — it must be a bare IPv6 address with only the low 64 bits set (e.g. ::42), and not ::";
        }
        {
          assertion = h.publicHostname == null || netLib.isHostname h.publicHostname;
          message = "router.hosts: device '${h.name}' public hostname '${toString h.publicHostname}' is not a valid DNS name (e.g. nas.example.com)";
        }
      ]
    ) cfg.hosts;

    warnings = map (
      h:
      "router.hosts: device '${h.name}' has a group or user assignment but no static IP — "
      + "device-tier access policies cannot apply to it (it follows its network's default policy)."
    ) (filter (h: h.staticIp == null && (h.group != null || h.user != null)) cfg.hosts);
  };
}
