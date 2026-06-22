// Ambient declarations: `cockpit` is provided at runtime by ../base1/cockpit.js,
// and the build derivation writes config.js which sets window.cockpitRouterConfig.
declare const cockpit: any;

interface Window {
  cockpitRouterConfig?: { adguardPort: number };
}

// Side-effect imports resolved by esbuild via pkg/lib (nodePaths) and the sass plugin.
declare module "cockpit-dark-theme";
declare module "patternfly/*";
declare module "*.scss";
declare module "*.css";
