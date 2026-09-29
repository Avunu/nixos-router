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
  // The settings the running generation was built from
  // (/etc/router/applied-settings.json); {} when that is unknown.
  applied: Json;
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

// Retired keys the router module still accepts but ignores, and the schema no
// longer allows (additionalProperties: false). The settings loader
// (lib/settings.nix) migrates them out of the file, but a router installed
// before the loader feeds its JSON to the module directly, so the key stays on
// disk — and every save would then fail schema validation.
const RETIRED_KEYS = ["dns.technitium.listenPort"];

// The settings without the retired keys, so the next save writes the current
// shape. Returns `obj` itself when it holds none of them.
export function dropRetiredKeys(obj: Json): Json {
  let next = obj;
  for (const path of RETIRED_KEYS) {
    const cut = path.lastIndexOf(".");
    const parentPath = path.slice(0, cut);
    const key = path.slice(cut + 1);
    const parent = getPath(next, parentPath);
    if (isObject(parent) && Object.hasOwn(parent, key)) {
      next = setPath(
        next,
        parentPath,
        Object.fromEntries(Object.entries(parent).filter(([k]) => k !== key)),
      );
    }
  }
  return next;
}

// A form's working copy rebuilt from the settings file on disk, keeping the
// edits it has not saved yet (useSettings). `pending` maps leaf paths to the
// values the admin set, in the order they were last set; it is updated in
// place: an edit the file already carries has been saved (by this form, or by
// a direct write of the working copy) and is dropped, so it is never
// re-applied over a later change such as a Discard of the saved changes. The
// rest are re-applied in order, which lets a later edit of a parent path win
// over an earlier edit inside it.
export function rebaseEdits(disk: Json, pending: Map<string, Json>): Json {
  let next = disk;
  for (const [path, val] of pending) {
    if (deepEqual(getPath(disk, path) ?? null, val)) {
      pending.delete(path);
    } else {
      next = setPath(next, path, val);
    }
  }
  return next;
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

// Apply `fn` to the settings on disk and to every unsaved edit alike, for a
// write made outside a form's working copy while the form may hold edits of
// the same section: an exception approved from Access Policies, a rule added
// from a Threat Protection event. Writing `fn(disk)` alone would leave a
// pending whole-section edit that, re-applied over the file (rebaseEdits),
// hides the change and saves it away on the next Save. `fn` sees the file
// with each edit in turn, so it must tolerate its change already being there.
export function patchWithEdits(
  disk: Json,
  pending: ReadonlyMap<string, Json>,
  fn: (settings: Json) => Json,
): { disk: Json; pending: Map<string, Json> } {
  const next = new Map<string, Json>();
  for (const [path, val] of pending) {
    const patched = fn(setPath(disk, path, val));
    next.set(path, getPath(patched, path) ?? null);
  }
  return { disk: fn(disk), pending: next };
}

// ── Leaf-level diff ─────────────────────────────────────────────────────────
// One step into the settings: an object key, a list position, or a list entry
// named by its `name` (hosts, groups, policies…), which is how an admin knows
// it and survives reordering.
export type PathSegment = string | number | { name: string };

export interface LeafChange {
  path: PathSegment[];
  before: Json | undefined; // undefined: absent before (added)
  after: Json | undefined; // undefined: absent after (removed)
}

// A list whose entries are objects with distinct string names.
function namesOf(list: Json[]): string[] | null {
  const names: string[] = [];
  for (const item of list) {
    const name = isObject(item) ? item["name"] : undefined;
    if (typeof name !== "string" || names.includes(name)) {
      return null;
    }
    names.push(name);
  }
  return names;
}

// What changed between two settings trees, down to the smallest part that
// still reads on its own: objects by key, named lists by entry name,
// same-length lists by position. Any other list is one change as a whole.
export function diffLeaves(
  before: Json | undefined,
  after: Json | undefined,
  path: PathSegment[] = [],
): LeafChange[] {
  if (deepEqual(before, after)) {
    return [];
  }
  if (isObject(before) && isObject(after)) {
    const keys = [...Object.keys(after), ...Object.keys(before).filter((k) => !(k in after))];
    return keys.flatMap((k) => diffLeaves(before[k], after[k], [...path, k]));
  }
  if (Array.isArray(before) && Array.isArray(after)) {
    const beforeNames = namesOf(before);
    const afterNames = namesOf(after);
    if (beforeNames && afterNames) {
      const byName = (list: Json[], names: string[], name: string) => list[names.indexOf(name)];
      const names = [...afterNames, ...beforeNames.filter((n) => !afterNames.includes(n))];
      return names.flatMap((name) =>
        diffLeaves(byName(before, beforeNames, name), byName(after, afterNames, name), [
          ...path,
          { name },
        ]),
      );
    }
    if (before.length === after.length) {
      return after.flatMap((item, i) => diffLeaves(before[i], item, [...path, i]));
    }
  }
  return [{ path, before, after }];
}

// Top-level keys that differ between the saved JSON and the running generation's.
export function changedTopKeys(desired: Json, applied: Json): string[] {
  const d = isObject(desired) ? desired : {};
  const a = isObject(applied) ? applied : {};
  const keys = new Set([...Object.keys(d), ...Object.keys(a)]);
  return [...keys].filter((k) => !deepEqual(d[k], a[k]));
}

// Can "Discard saved changes" copy the running generation's settings over the
// file? Not when they are empty: then there is nothing to go back to (the
// generation predates applied-settings.json, or this session cannot read it),
// and the copy would replace every setting with {}.
export function canRevertTo(applied: Json): boolean {
  return isObject(applied) && Object.keys(applied).length > 0;
}
