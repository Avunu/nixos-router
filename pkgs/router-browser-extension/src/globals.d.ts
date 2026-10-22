// Replaced at build time by esbuild's `define` (build.js): true in the Firefox
// bundle, false in the Chrome one. Only background.ts reads it; the logic it
// feeds (redirect.ts) takes the flag as a parameter so tests cover both.
declare const __FIREFOX__: boolean;
