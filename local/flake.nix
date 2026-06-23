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
      settings = builtins.fromJSON (builtins.readFile ./router-settings.json);
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
          { router = nixpkgs.lib.mkDefault settings; }

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
