// JSON Schema validation for the cockpit-managed router config.
//
// The schema (router-settings.schema.json) mirrors the serializable router.*
// options of the NixOS module, so an invalid config is caught here before it is
// written or applied — instead of failing later at `nixos-rebuild`. The validator
// is the Ajv standalone build (precompiled by build.js): no runtime codegen, so it
// runs under Cockpit's CSP, which forbids unsafe-eval.
import { validateRouterSettings } from "./_generated/validate-settings.js";
import type { Json } from "./nix";

// Returns human-readable schema errors (empty list = valid).
export function validateSettings(obj: Json): string[] {
  if (validateRouterSettings(obj)) {
    return [];
  }
  return (validateRouterSettings.errors ?? []).map((e) => {
    const where = e.instancePath || "(root)";
    return `${where}: ${e.message ?? "invalid"}`;
  });
}
