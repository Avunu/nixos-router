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
      hostName = "948-router";
      system = "x86_64-linux";
    in
    {
      nixosConfigurations = {
        "${hostName}" = nixpkgs.lib.nixosSystem {
          system = system;
          modules = [
            { nix.nixPath = [ "nixpkgs=${self.inputs.nixpkgs}" ]; }
            nixos-router.nixosModules.router
            # All `router.*` settings live in this separate module so the Cockpit
            # web UI can edit them in place (via nix-editor). Hand-edit it freely;
            # the UI only touches the options exposed by its Settings forms.
            ./router-settings.nix
          ];
        };
      };
    };
}
