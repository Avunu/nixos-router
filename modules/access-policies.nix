# ── Access Policies module ─────────────────────────────────────────────────────
# Named DNS filtering policies (Barracuda-style), assignable to device groups,
# directory groups, subnets, and/or networks. Policies are compiled — together
# with the device registry (hosts.nix) and synced directory state — into the
# Technitium Advanced Blocking app configuration by pkgs/router-dns-tools
# (`router-policy-compile`).
#
# One winning policy per client (Advanced Blocking maps each client to exactly
# one group, most-specific networkGroupMap prefix wins):
#   host group > directory group (of the device's user) > subnet/network >
#   accessPolicies.defaultPolicy; within a tier the highest `priority` wins.
#
# This module only defines options, validates them, and emits the *static*
# compiler inputs (`router-policy-static.json`, exposed to dns-technitium.nix
# via router._policyStaticInputs): policies with catalog references expanded to
# format-tagged URL lists, the registry, group names, and network CIDRs. The
# runtime merge with directory state happens in the compiler, never in Nix.
{
  config,
  lib,
  pkgs,
  ...
}:
with lib;
let
  cfg = config.router;
  inherit (config.router._internal)
    lanGW
    guestGW
    lanCIDR
    guestCIDR
    wgNets
    ;

  catalog = import ./filter-catalog.nix;

  # The "Base" policy used when none are configured: the modest default set
  # of ad, malware and phishing lists.
  synthesizedBase = {
    name = "Base";
    description = "Default policy";
    priority = 0;
    standardFilters = [
      "adguard_ads"
      "adguard_malware"
      "adguard_phishing"
    ];
    categories = [ ];
    blockListUrls = [ ];
    allowListUrls = [ ];
    adblockListUrls = [ ];
    regexBlockListUrls = [ ];
    blockDomains = [ ];
    allowDomains = [ ];
    blockRegex = [ ];
    allowRegex = [ ];
    responseType = "blockingAddress";
    blockingAddresses = [
      "0.0.0.0"
      "::"
    ];
    assignments = {
      networks = [ ];
      subnets = [ ];
      hostGroups = [ ];
      directoryGroups = [ ];
    };
  };

  effectivePolicies =
    if cfg.accessPolicies.policies == [ ] then [ synthesizedBase ] else cfg.accessPolicies.policies;
  policyNames = map (p: p.name) effectivePolicies;
  groupNames = map (g: g.name) cfg.hostGroups;

  # ── Catalog expansion ────────────────────────────────────
  # Resolve standardFilters keys and UT Capitole categories to concrete,
  # format-tagged URL lists. Advanced Blocking does not auto-detect list
  # syntax, so adblock-format catalog entries land in adblockListUrls and
  # hosts-format entries in blockListUrls.
  catalogUrls =
    format: keys:
    map (k: catalog.standardFilters.${k}.url) (
      filter (k: catalog.standardFilters.${k}.format == format) keys
    );

  expandPolicy = p: {
    inherit (p)
      name
      priority
      responseType
      blockingAddresses
      assignments
      ;
    allowed = p.allowDomains;
    blocked = p.blockDomains;
    allowedRegex = p.allowRegex;
    blockedRegex = p.blockRegex;
    allowListUrls = p.allowListUrls;
    blockListUrls =
      p.blockListUrls
      ++ catalogUrls "hosts" p.standardFilters
      ++ map catalog.utCapitole.urlFor p.categories;
    adblockListUrls = p.adblockListUrls ++ catalogUrls "adblock" p.standardFilters;
    regexBlockListUrls = p.regexBlockListUrls;
  };

  # ── Compiler static inputs ───────────────────────────────
  # Everything the runtime policy compiler needs except directory state.
  staticInputs = pkgs.writeText "router-policy-static.json" (
    builtins.toJSON {
      defaultPolicy = cfg.accessPolicies.defaultPolicy;
      policies = map expandPolicy effectivePolicies;
      hosts = map (h: {
        mac = toLower h.mac;
        inherit (h)
          name
          staticIp
          network
          group
          user
          ;
      }) cfg.hosts;
      hostGroups = groupNames;
      networks = {
        lan = {
          cidr = lanCIDR;
          gateway = lanGW;
        };
        guest = optionalAttrs cfg.guest.enable {
          cidr = guestCIDR;
          gateway = guestGW;
        };
        wireguard = wgNets;
      };
      blockDoHProviders = cfg.dns.technitium.blockDoHProviders or true;
      dohProviderDomains = catalog.dohProviderDomains;
      blockPage = cfg.accessPolicies.blockPage;
    }
  );

  policyType = types.submodule {
    options = {
      name = mkOption {
        type = types.strMatching "[A-Za-z0-9][A-Za-z0-9_ -]*";
        description = "Policy name (unique; becomes the Advanced Blocking group name).";
      };
      description = mkOption {
        type = types.str;
        default = "";
        description = "Free-form policy description.";
      };
      priority = mkOption {
        type = types.int;
        default = 0;
        description = "Tie-breaker within an assignment tier — higher wins.";
      };
      categories = mkOption {
        type = types.listOf (types.enum catalog.utCapitole.categories);
        default = [ ];
        description = "UT Capitole blacklist categories to block.";
      };
      standardFilters = mkOption {
        type = types.listOf (types.enum (attrNames catalog.standardFilters));
        default = [ ];
        description = "Standard filter catalog entries to enable (see filter-catalog.nix).";
      };
      blockListUrls = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Custom hosts/domain-format block list URLs.";
      };
      allowListUrls = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Custom hosts/domain-format allow list URLs.";
      };
      adblockListUrls = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Custom AdBlock/AdGuard-format list URLs.";
      };
      regexBlockListUrls = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Custom regex-format block list URLs.";
      };
      blockDomains = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Domains to block (with subdomains).";
      };
      allowDomains = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Domains to always allow (with subdomains); wins over blocks.";
      };
      blockRegex = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Regex patterns to block.";
      };
      allowRegex = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Regex patterns to always allow.";
      };
      responseType = mkOption {
        type = types.enum [
          "nxdomain"
          "blockingAddress"
        ];
        default = "blockingAddress";
        description = ''
          Blocked-query answer: NXDOMAIN, or the blocking addresses below.
          With the block page enabled, "blockingAddress" policies answer with
          the router's LAN IP so clients land on the block page.
        '';
      };
      blockingAddresses = mkOption {
        type = types.listOf types.str;
        default = [
          "0.0.0.0"
          "::"
        ];
        description = "A/AAAA answers for blocked queries (responseType = blockingAddress).";
      };
      assignments = {
        networks = mkOption {
          type = types.listOf (
            types.enum [
              "lan"
              "guest"
              "wireguard"
            ]
          );
          default = [ ];
          description = "Networks whose clients get this policy (unless a more specific tier matches).";
        };
        subnets = mkOption {
          type = types.listOf types.str;
          default = [ ];
          description = "Raw CIDR subnets this policy applies to.";
        };
        hostGroups = mkOption {
          type = types.listOf types.str;
          default = [ ];
          description = "Device groups (router.hostGroups) this policy applies to.";
        };
        directoryGroups = mkOption {
          type = types.listOf types.str;
          default = [ ];
          description = "Directory group names/ids whose members' devices get this policy.";
        };
      };
    };
  };
in
{
  options.router = {
    accessPolicies = {
      defaultPolicy = mkOption {
        type = types.str;
        default = "Base";
        description = "Policy applied to clients no other assignment matches.";
      };

      policies = mkOption {
        type = types.listOf policyType;
        default = [ ];
        description = ''
          Named access policies. When empty, a "Base" policy with a modest
          default set of ad, malware and phishing lists is synthesized.
        '';
      };

      blockPage = {
        enable = mkOption {
          type = types.bool;
          default = false;
          description = ''
            Serve a branded block page (Technitium Block Page app on the
            router's :80/:443). Policies with responseType "blockingAddress"
            answer with the router's LAN IP so clients land on the page, which
            includes an exception-request form handled by router-logd.
          '';
        };
        title = mkOption {
          type = types.str;
          default = "Website Blocked";
          description = "Block page browser title.";
        };
        heading = mkOption {
          type = types.str;
          default = "Website Blocked";
          description = "Block page heading.";
        };
        message = mkOption {
          type = types.str;
          default = "This website has been blocked by your network administrator.";
          description = "Block page body message.";
        };
        contactEmail = mkOption {
          type = types.str;
          default = "";
          description = "Contact shown on the block page (optional).";
        };
      };
    };

    # Store path of the compiler's static inputs, consumed by
    # dns-technitium.nix (reconcile/policy-push units). Internal plumbing —
    # `router._internal` is readOnly and owned by topology.nix, so this
    # lives in its own internal option.
    _policyStaticInputs = mkOption {
      type = types.path;
      internal = true;
      readOnly = true;
      description = "Generated router-policy-static.json for router-policy-compile.";
    };
  };

  config = {
    router._policyStaticInputs = staticInputs;

    assertions = [
      {
        assertion = length (unique policyNames) == length policyNames;
        message = "router.accessPolicies: duplicate policy name(s)";
      }
      {
        assertion = elem cfg.accessPolicies.defaultPolicy policyNames;
        message = "router.accessPolicies.defaultPolicy '${cfg.accessPolicies.defaultPolicy}' is not a defined policy (have: ${concatStringsSep ", " policyNames})";
      }
    ]
    ++ concatMap (p: [
      {
        assertion = all (g: elem g groupNames) p.assignments.hostGroups;
        message = "router.accessPolicies: policy '${p.name}' references undefined host group(s): ${
          concatStringsSep ", " (filter (g: !elem g groupNames) p.assignments.hostGroups)
        }";
      }
      {
        assertion = !(elem "guest" p.assignments.networks) || cfg.guest.enable;
        message = "router.accessPolicies: policy '${p.name}' is assigned to the guest network, but router.guest.enable is false";
      }
    ]) effectivePolicies;
  };
}
