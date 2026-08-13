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
{
  config,
  lib,
  ...
}:
with lib;
let
  cfg = config.router;

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
      ]
    ) cfg.hosts;

    warnings = map (
      h:
      "router.hosts: device '${h.name}' has a group or user assignment but no static IP — "
      + "device-tier access policies cannot apply to it (it follows its network's default policy)."
    ) (filter (h: h.staticIp == null && (h.group != null || h.user != null)) cfg.hosts);
  };
}
