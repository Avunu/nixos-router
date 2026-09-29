// How far a rebuild has got, read from its output as the journal delivers it.
//
// nixos-rebuild says little about progress, but Nix announces how many
// derivations it will build and paths it will fetch, then names each as it
// starts it, and switch-to-configuration announces the activation. That is
// enough for a phase and, while building, a count. Pure, so `node --test` can
// feed it recorded output.

export type Phase = "starting" | "updating" | "building" | "activating";

export interface RebuildProgress {
  phase: Phase;
  toBuild: number;
  built: number;
  toFetch: number;
  fetched: number;
}

export const INITIAL_PROGRESS: RebuildProgress = {
  phase: "starting",
  toBuild: 0,
  built: 0,
  toFetch: 0,
  fetched: 0,
};

const TO_BUILD = /^these (\d+) derivations will be built:/;
const TO_FETCH = /^these (\d+) paths will be fetched/;
const ACTIVATION =
  /^(stopping the following units|activating the configuration\.\.\.|setting up \/etc\.\.\.|restarting systemd\.\.\.)/;

// Only ever moves forward: a phase once reached is kept.
const RANK: Record<Phase, number> = { starting: 0, updating: 1, building: 2, activating: 3 };
const reach = (p: RebuildProgress, phase: Phase): Phase =>
  RANK[phase] > RANK[p.phase] ? phase : p.phase;

export function advanceProgress(p: RebuildProgress, rawLine: string): RebuildProgress {
  const line = rawLine.trim();
  if (line.startsWith(":: Updating flake inputs")) {
    return { ...p, phase: reach(p, "updating") };
  }
  if (line.startsWith("building the system configuration...")) {
    return { ...p, phase: reach(p, "building") };
  }
  if (ACTIVATION.test(line)) {
    return { ...p, phase: "activating" };
  }
  const toBuild = TO_BUILD.exec(line);
  if (toBuild) {
    return { ...p, phase: reach(p, "building"), toBuild: p.toBuild + Number(toBuild[1]) };
  }
  if (line === "this derivation will be built:") {
    return { ...p, phase: reach(p, "building"), toBuild: p.toBuild + 1 };
  }
  const toFetch = TO_FETCH.exec(line);
  if (toFetch) {
    return { ...p, phase: reach(p, "building"), toFetch: p.toFetch + Number(toFetch[1]) };
  }
  if (line.startsWith("this path will be fetched")) {
    return { ...p, phase: reach(p, "building"), toFetch: p.toFetch + 1 };
  }
  if (/^building '\/nix\/store\/[^']+\.drv'/.test(line)) {
    return { ...p, built: p.built + 1 };
  }
  if (/^copying path '\/nix\/store\/[^']+' from '/.test(line)) {
    return { ...p, fetched: p.fetched + 1 };
  }
  return p;
}

export function progressOf(lines: Iterable<string>, from = INITIAL_PROGRESS): RebuildProgress {
  let p = from;
  for (const line of lines) {
    p = advanceProgress(p, line);
  }
  return p;
}

// Share of the announced work done, 0–1, while building; null when there is
// no count to show (nothing announced yet, or another phase).
export function buildFraction(p: RebuildProgress): number | null {
  const total = p.toBuild + p.toFetch;
  if (p.phase !== "building" || total === 0) {
    return null;
  }
  return Math.min(1, (p.built + p.fetched) / total);
}
