// Pure settings-JSON helpers: path access, structural comparison, and
// locked-field detection.
//
// Split out of nix.ts so it can be imported without a browser: nix.ts reads
// `window.cockpitRouterConfig` at module scope and pulls in the generated Ajv
// validator, neither of which exists under `node --test`. Everything here is a
// total function over plain JSON, which is exactly the part worth testing —
// isLocked silently disabled the whole Access Policies page once already.
//
// nix.ts re-exports all of it, so importers are unaffected.
export type Json = string | number | boolean | null | Json[] | { [key: string]: Json };
export type JsonObject = Record<string, Json>;

const isObject = (v: Json | undefined): v is JsonObject =>
  typeof v === "object" && v !== null && !Array.isArray(v);

export interface SettingsState {
  desired: Json; // Editable JSON on disk (the saved state)
  effective: Json; // Applied effective values (module-emitted)
  applied: Json; // Snapshot written by the UI after the last apply
}

export function getPath(obj: Json, path: string): Json | undefined {
  let cur: Json | undefined = obj;
  for (const k of path.split(".")) {
    if (!isObject(cur)) {
      return undefined;
    }
    cur = cur[k];
  }
  return cur;
}

export function setPath(obj: Json, path: string, value: Json): Json {
  const keys = path.split(".");
  const clone: JsonObject = isObject(obj) ? structuredClone(obj) : {};
  let cur: JsonObject = clone;
  for (let i = 0; i < keys.length - 1; i++) {
    const k = keys[i]!;
    const next = cur[k];
    if (!isObject(next)) {
      cur[k] = {};
    }
    cur = cur[k] as JsonObject;
  }
  cur[keys.at(-1)!] = value;
  return clone;
}

export function deepEqual(a: Json | undefined, b: Json | undefined): boolean {
  if (a === b) {
    return true;
  }
  if (a === null || b === null || a === undefined || b === undefined) {
    return false;
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) {
      return false;
    }
    return a.every((x, i) => deepEqual(x, b[i]));
  }
  if (isObject(a) && isObject(b)) {
    const ka = Object.keys(a);
    const kb = Object.keys(b);
    if (ka.length !== kb.length) {
      return false;
    }
    return ka.every((k) => deepEqual(a[k], b[k]));
  }
  return false;
}

// A leaf is locked when the last-applied input set it but the effective config
// Disagrees — i.e. something in Nix overrode the JSON value.
// True when Nix OVERRODE something the settings JSON set — not merely when the
// module supplied a default the JSON omitted.
//
// That distinction is the whole point: effective.json is `genAttrs effectiveKeys
// (k: cfg.${k})`, the FULLY EVALUATED config, so it always carries defaults the
// JSON never mentions. Comparing whole subtrees with deepEqual therefore
// reported a lock for any section not spelled out exhaustively — which greyed
// out the entire Access Policies page, since it is the one caller that locks on
// a section path (`accessPolicies`) rather than a leaf. A migrated policy omits
// blockListUrls, allowRegex, blockingAddresses and friends, so it could never
// compare equal.
export function isLocked(state: SettingsState, path: string): boolean {
  const applied = getPath(state.applied, path);
  if (applied === undefined) {
    return false;
  }
  return !subsumes(getPath(state.effective, path), applied);
}

// Does `effective` contain everything `applied` sets, unchanged? Extra keys in
// `effective` are module defaults and are not overrides; a changed or missing
// value is. Arrays must match in length — Nix adding or dropping an element is
// a real change, not a default.
function subsumes(effective: Json | undefined, applied: Json | undefined): boolean {
  if (deepEqual(applied, effective)) {
    return true;
  }
  if (Array.isArray(applied) || Array.isArray(effective)) {
    return (
      Array.isArray(applied) &&
      Array.isArray(effective) &&
      applied.length === effective.length &&
      applied.every((x, i) => subsumes(effective[i], x))
    );
  }
  if (isObject(applied) && isObject(effective)) {
    return Object.keys(applied).every((k) => subsumes(effective[k], applied[k]));
  }
  return false;
}

// Which baseline should isLocked and the changes tray compare against?
//
// /var/lib/cockpit-router/applied.json is written only when a rebuild is
// applied FROM THE UI. A `nixos-rebuild switch` at the shell, the
// `system-upgrade` script and the nightly nixos-upgrade unit all leave it
// behind — and so does a UI apply whose rebuild exits non-zero, since the
// snapshot is written in the success branch. Once it lags, every path the JSON
// has changed since reads as "the effective config disagrees with what we
// asked for": isLocked reports a Nix override that does not exist (the whole
// interface-assignment table greys out with "locked in the Nix configuration")
// and the tray offers to apply changes that are already running.
//
// The settings file's own mtime settles it. When the running generation was
// activated no earlier than the last write to the JSON, that JSON *is* what the
// running system was built from, so it is the honest baseline — better than the
// snapshot, because it is never behind. A JSON newer than the generation means
// genuinely pending edits, and only there does the snapshot still carry
// information the JSON does not.
export function appliedBaseline(
  desired: Json,
  snapshot: Json,
  settingsMtime: number | null,
  systemMtime: number | null,
): { applied: Json; stale: boolean } {
  if (settingsMtime === null || systemMtime === null || settingsMtime > systemMtime) {
    return { applied: snapshot, stale: false };
  }
  return { applied: desired, stale: !deepEqual(snapshot, desired) };
}

// Top-level keys that differ between the saved JSON and the last applied snapshot.
export function changedTopKeys(desired: Json, applied: Json): string[] {
  const d = isObject(desired) ? desired : {};
  const a = isObject(applied) ? applied : {};
  const keys = new Set([...Object.keys(d), ...Object.keys(a)]);
  return [...keys].filter((k) => !deepEqual(d[k], a[k]));
}
