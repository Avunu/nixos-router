// Device-name rules that need no browser, mirroring modules/hosts.nix: a name
// is strMatching "[A-Za-z0-9][A-Za-z0-9_. -]*" and unique among router.hosts.
// The committed schema carries the pattern, so Ajv also refuses a bad name on
// save; these checks say which rule failed inline, as the user types, and catch
// duplicate names, which the schema can't.
//
// Checks return a code rather than a sentence, so this module stays free of
// `cockpit` (node --test runs it); hosts.tsx turns them into translated text.

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_. -]*$/;

export type HostNameIssue = "empty" | "pattern" | "duplicate";

// The editor saves the trimmed name, so that is what is checked. Uniqueness is
// exact, as in the module: "NAS" and "nas" are two names.
export function hostNameError(name: string, otherNames: readonly string[]): HostNameIssue | null {
  const n = name.trim();
  if (n === "") {
    return "empty";
  }
  if (!NAME_RE.test(n)) {
    return "pattern";
  }
  if (otherNames.includes(n)) {
    return "duplicate";
  }
  return null;
}

// A valid, unused default for the Adopt form, from the mDNS names a device
// announces (hosts.tsx joins the distinct ones with ", "). It takes the first
// name without its ".local" domain, drops accents, turns each run of other
// characters the pattern refuses into a dash, and trims separators from both
// ends. With nothing left it falls back to "device-" and the last three bytes
// of the MAC. A name another device holds gets "-2", "-3", … appended.
export function sanitizeHostName(liveName: string, mac: string, taken: readonly string[]): string {
  const first = liveName.split(",")[0] ?? "";
  const cleaned = first
    .trim()
    .replace(/\.local\.?$/i, "")
    .normalize("NFKD")
    .replaceAll(/\p{M}/gu, "")
    .replaceAll(/[^A-Za-z0-9_. -]+/g, "-")
    .replace(/^[^A-Za-z0-9]+/, "")
    .replace(/[-_. ]+$/, "");
  const base = cleaned || `device-${mac.replaceAll(":", "").slice(-6).toLowerCase()}`;
  let name = base;
  for (let i = 2; taken.includes(name); i += 1) {
    name = `${base}-${i}`;
  }
  return name;
}
