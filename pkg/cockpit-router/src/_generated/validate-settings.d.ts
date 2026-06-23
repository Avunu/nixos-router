// Type declaration for the generated Ajv standalone validator
// (src/_generated/validate-settings.js, produced by build.js). The .js itself is
// gitignored and regenerated every build; this committed declaration lets tsc and
// the linter resolve the import even when the generated file is absent.
import type { ErrorObject } from "ajv";

export const validateRouterSettings: ((data: unknown) => boolean) & {
  errors?: ErrorObject[] | null;
};
