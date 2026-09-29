// Unit tests for reading a rebuild's progress from its output.
import { test } from "node:test";
import assert from "node:assert/strict";

import { buildFraction, progressOf } from "./rebuild-progress.ts";

// An apply as nixos-rebuild-ng and Nix print it to the journal (trimmed).
const APPLY = [
  "building the system configuration...",
  "these 3 derivations will be built:",
  "  /nix/store/aaa-etc.drv",
  "  /nix/store/bbb-nixos-system.drv",
  "  /nix/store/ccc-router-rebuild.drv",
  "these 2 paths will be fetched (1.20 MiB download, 5.10 MiB unpacked):",
  "  /nix/store/ddd-jq-1.8.2",
  "copying path '/nix/store/ddd-jq-1.8.2' from 'https://cache.nixos.org'...",
  "building '/nix/store/aaa-etc.drv'...",
];

void test("progress: phases follow the output and never go back", () => {
  assert.equal(progressOf([]).phase, "starting");
  assert.equal(progressOf([":: Updating flake inputs in /etc/nixos"]).phase, "updating");
  const building = progressOf(APPLY);
  assert.deepEqual(building, { phase: "building", toBuild: 3, built: 1, toFetch: 2, fetched: 1 });
  assert.equal(buildFraction(building), 2 / 5);
  const activating = progressOf([
    ...APPLY,
    "stopping the following units: foo.service",
    "building '/nix/store/x.drv'...",
  ]);
  assert.equal(activating.phase, "activating");
  assert.equal(buildFraction(activating), null);
});

void test("progress: no count until Nix announces one", () => {
  assert.equal(buildFraction(progressOf(["building the system configuration..."])), null);
  assert.deepEqual(
    progressOf(["this derivation will be built:", "this path will be fetched (0.1 MiB):"]),
    {
      phase: "building",
      toBuild: 1,
      built: 0,
      toFetch: 1,
      fetched: 0,
    },
  );
});
