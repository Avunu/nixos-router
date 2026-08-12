"""Runtime tooling for the nixos-router access-protection stack.

CLIs (all driven by one Nix-generated runtime config JSON):
  router-technitium-reconcile — assert Technitium settings/zones/apps/tokens
  router-policy-push          — recompile + push Advanced Blocking only
  router-policy-compile       — print the compiled Advanced Blocking config
  router-logd                 — query-log store (DuckDB) + block-page portal
  router-directory-sync       — pull users/groups from LDAP/Entra/Google
  router-report               — Typst PDF reports + Cloudflare email delivery
"""
