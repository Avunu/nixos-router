{
  # The project's binary cache, for the build `deploy.sh` runs on the
  # operator's machine: nixos-anywhere builds THIS flake, and only the flake
  # being built has its nixConfig read. Once installed, the router module
  # configures the same cache on the router itself.
  nixConfig = {
    extra-substituters = [ "https://nixos-router.cachix.org" ];
    extra-trusted-public-keys = [
      "nixos-router.cachix.org-1:SVg1w5V/8cCwagilNr0r64yhGEjnP/p71J10ULx9v+o="
    ];
  };

  inputs = {
    nixos-router.url = "github:Avunu/nixos-router";
    # nixpkgs is nixos-router's own, locked in that repository and tested and
    # cached by its CI. Updating nixos-router therefore updates nixpkgs to a
    # rev whose router-specific builds (the Technitium apps, the Cockpit
    # plugin) are already on the binary cache, and whose Technitium DNS
    # server matches the apps compiled against it.
    nixpkgs.follows = "nixos-router/nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      nixos-router,
    }:
    let
      system = "x86_64-linux";

      router = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          { nix.nixPath = [ "nixpkgs=${self.inputs.nixpkgs}" ]; }
          nixos-router.nixosModules.router

          # The cockpit-managed router config. The web UI reads and writes this
          # same JSON file (deployed to /etc/nixos/router-settings.json); edit it
          # by hand or from Cockpit. Its values are applied as defaults, so
          # anything set in the "locked settings" module below overrides them —
          # and such overridden fields show as read-only in the Cockpit UI.
          #
          # Always load it through nixos-router.lib: settings written for an
          # older version of the module are upgraded on the way in (and the file
          # itself rewritten at activation), so a module update never fails on
          # them.
          (nixos-router.lib.settingsModule ./router-settings.json)

          # Locked / non-serializable settings live here in Nix; the Cockpit UI
          # cannot change them. The Cockpit web UI itself (transport, port,
          # origins) is configured here rather than in the JSON, as are any
          # package-typed options (extraPackages, cockpit.package/plugins).
          (
            { config, ... }:
            {
              router.cockpit = {
                enable = true;
                port = 9090;
                allowedOrigins = [ "https://${config.router.hostName}.${config.router.lan.domain}:9090" ];
              };
              # router.wan.interface = "enp0s20f0";   # example: lock the WAN NIC
              # router.extraPackages = with nixpkgs.legacyPackages.${system}; [ ];
            }
          )
        ];
      };
    in
    {
      # Named after the router's own hostName (router-settings.json), read from
      # the evaluated system, so the settings file is loaded exactly once. That
      # is the name `system-upgrade`, the nightly auto-upgrade and Cockpit's
      # Apply build (`/etc/nixos#<hostName>`); `default` is a stable alias that
      # does not depend on it.
      nixosConfigurations = {
        ${router.config.networking.hostName} = router;
        default = router;
      };
    };
}
