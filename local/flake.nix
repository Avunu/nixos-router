{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    nixos-router = {
      url = "github:Avunu/nixos-router";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      nixos-router,
    }:
    let
      system = "x86_64-linux";
      # The cockpit-managed router config. The web UI reads and writes this same
      # JSON file (deployed to /etc/nixos/router-settings.json); on rebuild its
      # values flow into the router module below. Edit it by hand or from Cockpit.
      #
      # Always read it through nixos-router.lib: settings written for an older
      # version of the module are upgraded on the way in (and the file itself
      # rewritten at activation), so a module update never fails on them.
      settings = nixos-router.lib.readSettings ./router-settings.json;
    in
    {
      nixosConfigurations.${settings.hostName} = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          { nix.nixPath = [ "nixpkgs=${self.inputs.nixpkgs}" ]; }
          nixos-router.nixosModules.router

          # JSON-managed settings, applied as defaults so that anything you set
          # normally in the "locked settings" module below overrides them — and
          # such overridden fields show as read-only in the Cockpit UI.
          (nixos-router.lib.settingsModule ./router-settings.json)

          # Locked / non-serializable settings live here in Nix; the Cockpit UI
          # cannot change them. The Cockpit web UI itself (transport, port,
          # origins) is configured here rather than in the JSON, as are any
          # package-typed options (extraPackages, cockpit.package/plugins).
          {
            router.cockpit = {
              enable = true;
              port = 9090;
              allowedOrigins = [ "https://${settings.hostName}.lan:9090" ];
            };
            # router.wan.interface = "enp0s20f0";   # example: lock the WAN NIC
            # router.extraPackages = with nixpkgs.legacyPackages.${system}; [ ];
          }
        ];
      };
    };
}
