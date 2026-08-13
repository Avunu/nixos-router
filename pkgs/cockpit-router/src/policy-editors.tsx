// Shared editor pieces for the Access Policies page: labels for the standard
// filter catalog (filter-catalog.nix keys), a switch list bound to a policy's
// `standardFilters` array of enabled keys, the UT Capitole category selector
// (ported from the retired AdGuard page), and an editor for the four custom
// list-URL arrays a policy carries (block / allow / adblock / regex-block).
import { useState } from "react";
import utCapitoleCategories from "./ut-capitole.json";
import {
  Button,
  FormSelect,
  FormSelectOption,
  Gallery,
  Split,
  SplitItem,
  Switch,
  TextInput,
} from "@patternfly/react-core";
import type { AccessPolicy } from "./types";

const _ = cockpit.gettext;

// Labels for the standard filter catalog keys (the enum behind
// accessPolicies.policies[].standardFilters — see filter-catalog.nix).
export const FILTER_LABELS: Record<string, string> = {
  adaway: "AdAway hosts list",
  adguard_ads: "AdGuard Base (ads & trackers)",
  adguard_anti_malware: "Dandelion Sprout Anti-Malware",
  adguard_malware: "AdGuard Malware",
  adguard_hacked_sites: "Big List of Hacked Malware Sites",
  adguard_phishing: "AdGuard Phishing URL Blocklist",
  phishtank_openphish: "Phishing Army (PhishTank + OpenPhish)",
  steven_black: "Steven Black unified hosts",
  yoyo_adservers: "Peter Lowe's ad/tracker list",
};

// Switch list over the standard filter catalog, bound to the array of enabled
// catalog keys (a policy's `standardFilters`).
export const StandardFiltersSelector = ({
  value,
  onChange,
  isDisabled,
}: {
  value: string[];
  onChange: (v: string[]) => void;
  isDisabled?: boolean;
}) => {
  const selected = new Set(value);
  return (
    <Gallery hasGutter minWidths={{ default: "320px" }}>
      {Object.entries(FILTER_LABELS).map(([key, label]) => (
        <Switch
          key={key}
          id={`stdf-${key}`}
          label={_(label)}
          isChecked={selected.has(key)}
          isDisabled={isDisabled}
          onChange={(_e, on) => onChange(on ? [...value, key] : value.filter((k) => k !== key))}
        />
      ))}
    </Gallery>
  );
};

// Toggle-switch selector for UT Capitole blacklist categories. The list (id +
// official description) lives in ut-capitole.json — the single source also used
// at build time to inject the schema's allowed-values enum.
export const UtCapitoleSelector = ({
  value,
  onChange,
  isDisabled,
}: {
  value: string[];
  onChange: (v: string[]) => void;
  isDisabled?: boolean;
}) => {
  const selected = new Set(value);
  return (
    <Gallery hasGutter minWidths={{ default: "320px" }}>
      {utCapitoleCategories.map((c) => (
        <div key={c.id}>
          <Switch
            id={`utc-${c.id}`}
            label={c.id}
            isChecked={selected.has(c.id)}
            isDisabled={isDisabled}
            onChange={(_e, on) => onChange(on ? [...value, c.id] : value.filter((x) => x !== c.id))}
          />
          <div
            className="pf-v6-u-color-200"
            style={{ fontSize: "0.85rem", marginBlockStart: "0.125rem" }}
          >
            {c.description}
          </div>
        </div>
      ))}
    </Gallery>
  );
};

// ── custom list-URL editor ───────────────────────────────────────────────────
// A policy stores its custom filter lists as four separate URL arrays; the
// editor presents them as uniform rows of kind + URL.
export type UrlListKind =
  | "blockListUrls"
  | "allowListUrls"
  | "adblockListUrls"
  | "regexBlockListUrls";

export const URL_KIND_LABELS: Record<UrlListKind, string> = {
  blockListUrls: "Block list (hosts format)",
  allowListUrls: "Allow list",
  adblockListUrls: "AdBlock format",
  regexBlockListUrls: "Regex block list",
};

const URL_KINDS = Object.keys(URL_KIND_LABELS) as UrlListKind[];

interface UrlRow {
  kind: UrlListKind;
  url: string;
}

const toRows = (policy: AccessPolicy): UrlRow[] =>
  URL_KINDS.flatMap((kind) => (policy[kind] ?? []).map((url) => ({ kind, url })));

const fromRows = (rows: UrlRow[]): Record<UrlListKind, string[]> => {
  const lists: Record<UrlListKind, string[]> = {
    blockListUrls: [],
    allowListUrls: [],
    adblockListUrls: [],
    regexBlockListUrls: [],
  };
  for (const { kind, url } of rows) {
    lists[kind].push(url);
  }
  return lists;
};

// Rows of URL + kind select over the four custom list arrays of a policy.
// Reads the arrays from `policy` and hands the rebuilt four-array patch to
// `onChange` (mergeable into the policy object).
export const UrlListEditor = ({
  policy,
  onChange,
  isDisabled,
}: {
  policy: AccessPolicy;
  onChange: (lists: Record<UrlListKind, string[]>) => void;
  isDisabled?: boolean;
}) => {
  const [draftKind, setDraftKind] = useState<UrlListKind>("blockListUrls");
  const [draftUrl, setDraftUrl] = useState("");
  const rows = toRows(policy);
  const commit = (next: UrlRow[]) => onChange(fromRows(next));
  const setRow = (i: number, patch: Partial<UrlRow>) =>
    commit(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const add = () => {
    const url = draftUrl.trim();
    if (!url) {
      return;
    }
    commit([...rows, { kind: draftKind, url }]);
    setDraftUrl("");
  };

  const kindSelect = (
    value: UrlListKind,
    ariaLabel: string,
    onKind: (kind: UrlListKind) => void,
  ) => (
    <FormSelect
      value={value}
      isDisabled={isDisabled}
      onChange={(_e, v) => onKind(v as UrlListKind)}
      aria-label={ariaLabel}
      style={{ minWidth: "14rem" }}
    >
      {URL_KINDS.map((kind) => (
        <FormSelectOption key={kind} value={kind} label={_(URL_KIND_LABELS[kind])} />
      ))}
    </FormSelect>
  );

  return (
    <>
      {rows.map((row, i) => (
        <Split hasGutter key={i} style={{ marginBlockEnd: "0.5rem", alignItems: "center" }}>
          <SplitItem>
            {kindSelect(row.kind, _("List kind"), (kind) => setRow(i, { kind }))}
          </SplitItem>
          <SplitItem isFilled>
            <TextInput
              aria-label={_("List URL")}
              placeholder="https://…"
              value={row.url}
              isDisabled={isDisabled}
              onChange={(_e, v) => setRow(i, { url: v })}
            />
          </SplitItem>
          <SplitItem>
            <Button
              variant="link"
              isInline
              isDanger
              isDisabled={isDisabled}
              onClick={() => commit(rows.filter((_r, j) => j !== i))}
            >
              {_("Remove")}
            </Button>
          </SplitItem>
        </Split>
      ))}
      {rows.length === 0 && (
        <div className="pf-v6-u-color-200" style={{ marginBlockEnd: "0.5rem" }}>
          {_("No custom lists.")}
        </div>
      )}
      {!isDisabled && (
        <Split hasGutter style={{ alignItems: "center" }}>
          <SplitItem>{kindSelect(draftKind, _("New list kind"), setDraftKind)}</SplitItem>
          <SplitItem isFilled>
            <TextInput
              aria-label={_("New list URL")}
              placeholder="https://…"
              value={draftUrl}
              onChange={(_e, v) => setDraftUrl(v)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  add();
                }
              }}
            />
          </SplitItem>
          <SplitItem>
            <Button variant="secondary" onClick={add} isDisabled={!draftUrl.trim()}>
              {_("Add list")}
            </Button>
          </SplitItem>
        </Split>
      )}
    </>
  );
};
