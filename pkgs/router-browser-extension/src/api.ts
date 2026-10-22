// The extension API namespace. Firefox's `browser` is promise-based by
// definition; Chrome's `chrome` is promise-based for every API this extension
// uses from Chrome 120 (the manifest's minimum). Preferring `browser` where it
// exists means neither browser relies on the other's compatibility shim.
//
// Only the two entry points (background.ts, options.ts) import this; the
// modules they share take what they need as parameters, so tests never touch a
// browser global.

export const api: typeof chrome = (globalThis as { browser?: typeof chrome }).browser ?? chrome;
