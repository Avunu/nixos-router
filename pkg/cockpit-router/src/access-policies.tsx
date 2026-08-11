// Access Policies page — Barracuda-style DNS filtering over Technitium.
//
// Four sub-tabs:
//   • Policies           — named policies (filters + assignments), master-detail
//   • Preview            — resolve which policy a device / IP / user would get
//   • DNS settings       — upstreams, ports, SafeSearch, DoH blocking, block page
//   • Exception requests — approve/deny requests from the block page portal
//
// Policies/DNS settings edit the accessPolicies / dns sections of the settings
// JSON through the shared store (nix.ts); the backend policy compiler turns
// them into the DNS engine config on the next rebuild (changes tray).
import { useCallback, useEffect, useRef, useState } from "react";
import {
  Alert,
  Button,
  Card,
  CardBody,
  CardTitle,
  Checkbox,
  EmptyState,
  EmptyStateBody,
  Form,
  FormGroup,
  FormHelperText,
  FormSection,
  FormSelect,
  FormSelectOption,
  HelperText,
  HelperTextItem,
  Label,
  LabelGroup,
  MenuToggle,
  NumberInput,
  Select,
  SelectList,
  SelectOption,
  Split,
  SplitItem,
  Stack,
  StackItem,
  Switch,
  TextArea,
  TextInput,
  TextInputGroup,
  TextInputGroupMain,
  Tooltip,
} from "@patternfly/react-core";
import { Table, Thead, Tbody, Tr, Th, Td } from "@patternfly/react-table";
import { useSettings, ListEditor, Loading, SubNav, SaveBar, hint, TabbedPage } from "./settings";
import { errMsg, setPath, writeDesired } from "./nix";
import { loadDirectoryAll } from "./directory";
import type { Json } from "./nix";
import { exceptionRequests, setExceptionStatus } from "./logd";
import { resolvePolicy } from "./policy-resolver";
import type { MatchStep, NetworkCidrs } from "./policy-resolver";
import { StandardFiltersSelector, UtCapitoleSelector, UrlListEditor } from "./policy-editors";
import type {
  AccessPoliciesSection,
  AccessPolicy,
  DirectoryState,
  ExceptionRequest,
  HostGroup,
  PolicyAssignments,
  RouterHost,
} from "./types";

const _ = cockpit.gettext;

type PolicyNetwork = "lan" | "guest" | "wireguard";

// ── shared helpers ───────────────────────────────────────────────────────────
const fmtTime = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
};

type Settings = ReturnType<typeof useSettings>;

const sectionOf = (s: Settings): AccessPoliciesSection =>
  s.valueOf<AccessPoliciesSection>("accessPolicies", {});

const writeSection = (s: Settings, sec: AccessPoliciesSection) =>
  s.setLeaf("accessPolicies", sec as unknown as Json);

// Network CIDRs the resolver matches "networks" assignments against, derived
// from the lan/guest/wireguard settings sections.
function networkCidrs(s: Settings): NetworkCidrs {
  const cidrs: NetworkCidrs = {};
  const lanNet = s.valueOf("lan.networkAddress", "");
  if (lanNet) {
    cidrs.lan = `${lanNet}/${s.valueOf("lan.prefixLength", 24)}`;
  }
  if (s.valueOf("guest.enable", false)) {
    const guestNet = s.valueOf("guest.networkAddress", "");
    if (guestNet) {
      cidrs.guest = `${guestNet}/${s.valueOf("guest.prefixLength", 24)}`;
    }
  }
  const tunnels = s.valueOf<Record<string, { address?: string }>>("wireguard", {});
  cidrs.wireguard = Object.values(tunnels)
    .map((t) => t.address ?? "")
    .filter((a) => a !== "");
  return cidrs;
}

// Directory sync state + status — read-only runtime data; tolerate missing or
// unreadable files (directory sync disabled / never ran). `unresolved` names
// the references the last sync could not resolve, which is the only way to tell
// a group nobody has used yet from a typo: SSSD is never enumerated, so
// `state.groups` holds only groups already referenced AND resolved.
function useDirectory(): { state: DirectoryState | null; unresolved: string[] } {
  const [dir, setDir] = useState<{ state: DirectoryState | null; unresolved: string[] }>({
    state: null,
    unresolved: [],
  });
  useEffect(() => {
    void loadDirectoryAll()
      .then(({ state, status }) =>
        setDir({
          state: state && Array.isArray(state.users) && Array.isArray(state.groups) ? state : null,
          unresolved: Array.isArray(status?.unresolved) ? status.unresolved : [],
        }),
      )
      .catch(() => {});
  }, []);
  return dir;
}

const emptyPolicy = (name: string): AccessPolicy => ({
  name,
  description: "",
  priority: 0,
  categories: [],
  standardFilters: [],
  blockListUrls: [],
  allowListUrls: [],
  adblockListUrls: [],
  regexBlockListUrls: [],
  blockDomains: [],
  allowDomains: [],
  blockRegex: [],
  allowRegex: [],
  responseType: "blockingAddress",
  blockingAddresses: ["0.0.0.0", "::"],
  assignments: { networks: [], subnets: [], hostGroups: [], directoryGroups: [] },
});

const uniqueName = (base: string, taken: string[]): string => {
  if (!taken.includes(base)) {
    return base;
  }
  let n = 2;
  while (taken.includes(`${base} ${n}`)) {
    n += 1;
  }
  return `${base} ${n}`;
};

function sumLengths(lists: (string[] | undefined)[]): number {
  let total = 0;
  for (const list of lists) {
    total += list?.length ?? 0;
  }
  return total;
}

// ── summary chips for the policies table ────────────────────────────────────
const FiltersSummary = ({ policy }: { policy: AccessPolicy }) => {
  const lists = sumLengths([
    policy.blockListUrls,
    policy.allowListUrls,
    policy.adblockListUrls,
    policy.regexBlockListUrls,
  ]);
  const rules = sumLengths([
    policy.blockDomains,
    policy.allowDomains,
    policy.blockRegex,
    policy.allowRegex,
  ]);
  return (
    <LabelGroup numLabels={4}>
      <Label isCompact>{cockpit.format(_("$0 categories"), policy.categories?.length ?? 0)}</Label>
      <Label isCompact>
        {cockpit.format(_("$0 filters"), policy.standardFilters?.length ?? 0)}
      </Label>
      <Label isCompact>{cockpit.format(_("$0 lists"), lists)}</Label>
      <Label isCompact>{cockpit.format(_("$0 rules"), rules)}</Label>
    </LabelGroup>
  );
};

const AssignmentsSummary = ({ assignments }: { assignments?: PolicyAssignments }) => {
  const networks = assignments?.networks ?? [];
  const subnets = assignments?.subnets ?? [];
  const hostGroups = assignments?.hostGroups ?? [];
  const directoryGroups = assignments?.directoryGroups ?? [];
  if (networks.length + subnets.length + hostGroups.length + directoryGroups.length === 0) {
    return <span className="pf-v6-u-color-200">{_("None")}</span>;
  }
  return (
    <LabelGroup numLabels={8}>
      {networks.map((n) => (
        <Label key={`n-${n}`} color="blue" isCompact>
          {n}
        </Label>
      ))}
      {subnets.map((c) => (
        <Label key={`s-${c}`} color="grey" isCompact>
          {c}
        </Label>
      ))}
      {hostGroups.map((g) => (
        <Label key={`h-${g}`} color="green" isCompact>
          {g}
        </Label>
      ))}
      {directoryGroups.map((g) => (
        <Label key={`d-${g}`} color="purple" isCompact>
          {g}
        </Label>
      ))}
    </LabelGroup>
  );
};

// ── multi-select widgets (PF6 composable Select) ────────────────────────────
const CheckboxMultiSelect = ({
  options,
  selected,
  onChange,
  placeholder,
  isDisabled,
}: {
  options: string[];
  selected: string[];
  onChange: (v: string[]) => void;
  placeholder: string;
  isDisabled?: boolean;
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const toggleRef = useRef<HTMLButtonElement>(null);
  const toggleValue = (name: string) =>
    onChange(selected.includes(name) ? selected.filter((x) => x !== name) : [...selected, name]);
  return (
    <Select
      role="menu"
      isOpen={isOpen}
      selected={selected}
      onSelect={(_e, value) => toggleValue(String(value))}
      onOpenChange={setIsOpen}
      toggle={{
        toggleRef,
        toggleNode: (
          <MenuToggle
            ref={toggleRef}
            onClick={() => setIsOpen(!isOpen)}
            isExpanded={isOpen}
            isDisabled={isDisabled}
            isFullWidth
          >
            {selected.length > 0 ? selected.join(", ") : placeholder}
          </MenuToggle>
        ),
      }}
    >
      <SelectList>
        {options.length === 0 ? (
          <SelectOption isDisabled value="">
            {_("No groups defined")}
          </SelectOption>
        ) : (
          options.map((o) => (
            <SelectOption key={o} value={o} hasCheckbox isSelected={selected.includes(o)}>
              {o}
            </SelectOption>
          ))
        )}
      </SelectList>
    </Select>
  );
};

// Stable empty default for TypeaheadMultiSelect's optional list prop — an
// inline [] would be a new reference on every render.
const NO_UNRESOLVED: string[] = [];

const TypeaheadMultiSelect = ({
  options,
  unresolved = NO_UNRESOLVED,
  isCreatable = false,
  selected,
  onChange,
  placeholder,
  isDisabled,
}: {
  options: string[];
  // Names the last directory sync could not resolve — rendered as warning chips.
  unresolved?: string[];
  // Allow entries that are not in `options`. REQUIRED for directory groups:
  // `options` only lists groups a policy already references, so on a fresh
  // install it is empty and a closed list could never accept the first group.
  isCreatable?: boolean;
  selected: string[];
  onChange: (v: string[]) => void;
  placeholder: string;
  isDisabled?: boolean;
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [inputValue, setInputValue] = useState("");
  const toggleRef = useRef<HTMLButtonElement>(null);
  const filter = inputValue.trim().toLowerCase();
  const filtered = options.filter((o) => !filter || o.toLowerCase().includes(filter));
  const isBad = (name: string) => unresolved.some((u) => u.toLowerCase() === name.toLowerCase());
  const canCreate =
    isCreatable &&
    filter !== "" &&
    !options.some((o) => o.toLowerCase() === filter) &&
    !selected.some((x) => x.toLowerCase() === filter);
  const toggleValue = (name: string) => {
    onChange(selected.includes(name) ? selected.filter((x) => x !== name) : [...selected, name]);
    setInputValue("");
  };
  return (
    <Select
      variant="typeahead"
      isOpen={isOpen}
      selected={selected}
      onSelect={(_e, value) => toggleValue(String(value))}
      onOpenChange={(open) => {
        setIsOpen(open);
        if (!open) {
          setInputValue("");
        }
      }}
      toggle={{
        toggleRef,
        toggleNode: (
          <MenuToggle
            ref={toggleRef}
            variant="typeahead"
            onClick={() => setIsOpen(!isOpen)}
            isExpanded={isOpen}
            isDisabled={isDisabled}
            isFullWidth
          >
            <TextInputGroup isPlain>
              <TextInputGroupMain
                value={inputValue}
                onClick={() => setIsOpen(true)}
                onChange={(_e, v) => {
                  setInputValue(v);
                  setIsOpen(true);
                }}
                autoComplete="off"
                placeholder={placeholder}
                role="combobox"
                isExpanded={isOpen}
                aria-label={placeholder}
              >
                {selected.length > 0 && (
                  <LabelGroup numLabels={8} aria-label={_("Selected groups")}>
                    {selected.map((name) => (
                      <Label
                        key={name}
                        variant="outline"
                        color={isBad(name) ? "orange" : undefined}
                        title={
                          isBad(name)
                            ? _("The last directory sync could not resolve this group name.")
                            : undefined
                        }
                        onClose={(e) => {
                          e.stopPropagation();
                          onChange(selected.filter((x) => x !== name));
                        }}
                      >
                        {name}
                      </Label>
                    ))}
                  </LabelGroup>
                )}
              </TextInputGroupMain>
            </TextInputGroup>
          </MenuToggle>
        ),
      }}
    >
      <SelectList>
        {canCreate && (
          <SelectOption key={`__create-${filter}`} value={inputValue.trim()}>
            {cockpit.format(_('Use "$0"'), inputValue.trim())}
          </SelectOption>
        )}
        {filtered.length === 0 ? (
          <SelectOption isDisabled value="">
            {isCreatable
              ? _(
                  "No resolved group matches — type the group name exactly as the directory spells it.",
                )
              : filter
                ? cockpit.format(_('No groups match "$0"'), inputValue.trim())
                : _("No groups available")}
          </SelectOption>
        ) : (
          filtered.map((o) => (
            <SelectOption key={o} value={o} hasCheckbox isSelected={selected.includes(o)}>
              {o}
            </SelectOption>
          ))
        )}
      </SelectList>
    </Select>
  );
};

// ── policy editor (inline detail card) ──────────────────────────────────────
const PolicyEditorCard = ({
  policy,
  nameError,
  isDefault,
  guestEnabled,
  hostGroupOptions,
  directoryGroupOptions,
  directoryUnresolved,
  isDisabled,
  onPatch,
  onMakeDefault,
  onClose,
}: {
  policy: AccessPolicy;
  nameError: string;
  isDefault: boolean;
  guestEnabled: boolean;
  hostGroupOptions: string[];
  directoryGroupOptions: string[];
  directoryUnresolved: string[];
  isDisabled: boolean;
  onPatch: (patch: Partial<AccessPolicy>) => void;
  onMakeDefault: () => void;
  onClose: () => void;
}) => {
  const assignments = policy.assignments ?? {};
  const networks = assignments.networks ?? [];
  const patchAssignments = (patch: Partial<PolicyAssignments>) =>
    onPatch({ assignments: { ...assignments, ...patch } });
  const toggleNetwork = (net: PolicyNetwork, on: boolean) =>
    patchAssignments({ networks: on ? [...networks, net] : networks.filter((x) => x !== net) });
  const responseType = policy.responseType ?? "blockingAddress";

  return (
    <Card isCompact>
      <CardTitle>
        <Split hasGutter>
          <SplitItem isFilled>{cockpit.format(_("Edit policy: $0"), policy.name)}</SplitItem>
          <SplitItem>
            <Button variant="link" isInline onClick={onClose}>
              {_("Close")}
            </Button>
          </SplitItem>
        </Split>
      </CardTitle>
      <CardBody>
        <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
          <FormSection title={_("General")} titleElement="h3">
            <FormGroup label={_("Name")} fieldId="ap-name">
              <TextInput
                id="ap-name"
                value={policy.name}
                isDisabled={isDisabled}
                validated={nameError ? "error" : "default"}
                onChange={(_e, v) => onPatch({ name: v })}
              />
              {nameError && (
                <FormHelperText>
                  <HelperText>
                    <HelperTextItem variant="error">{nameError}</HelperTextItem>
                  </HelperText>
                </FormHelperText>
              )}
            </FormGroup>
            <FormGroup label={_("Description")} fieldId="ap-desc">
              <TextInput
                id="ap-desc"
                value={policy.description ?? ""}
                isDisabled={isDisabled}
                onChange={(_e, v) => onPatch({ description: v })}
              />
            </FormGroup>
            <FormGroup
              label={_("Priority")}
              fieldId="ap-priority"
              labelHelp={hint(_("Tie-breaker within an assignment tier — higher wins."))}
            >
              <NumberInput
                id="ap-priority"
                value={policy.priority ?? 0}
                isDisabled={isDisabled}
                widthChars={6}
                onMinus={() => onPatch({ priority: (policy.priority ?? 0) - 1 })}
                onPlus={() => onPatch({ priority: (policy.priority ?? 0) + 1 })}
                onChange={(e) => {
                  const n = Number((e.target as HTMLInputElement).value);
                  if (Number.isFinite(n)) {
                    onPatch({ priority: Math.trunc(n) });
                  }
                }}
                inputAriaLabel={_("Priority")}
              />
            </FormGroup>
            <FormGroup
              label={_("Default policy")}
              fieldId="ap-default"
              labelHelp={hint(
                _(
                  "The default policy applies to clients no other assignment matches. To move the default, open the other policy and enable this switch there.",
                ),
              )}
            >
              <Switch
                id="ap-default"
                label={
                  isDefault ? _("This is the default policy") : _("Make this the default policy")
                }
                isChecked={isDefault}
                isDisabled={isDisabled || isDefault}
                onChange={(_e, c) => {
                  if (c) {
                    onMakeDefault();
                  }
                }}
              />
            </FormGroup>
          </FormSection>

          <FormSection title={_("Categories")} titleElement="h3">
            <FormGroup
              label={_("UT Capitole categories")}
              fieldId="ap-categories"
              labelHelp={hint(_("Category names from dsi.ut-capitole.fr/blacklists"))}
            >
              <UtCapitoleSelector
                value={policy.categories ?? []}
                isDisabled={isDisabled}
                onChange={(v) => onPatch({ categories: v })}
              />
            </FormGroup>
          </FormSection>

          <FormSection title={_("Standard filters")} titleElement="h3">
            <StandardFiltersSelector
              value={policy.standardFilters ?? []}
              isDisabled={isDisabled}
              onChange={(v) => onPatch({ standardFilters: v })}
            />
          </FormSection>

          <FormSection title={_("Custom lists")} titleElement="h3">
            <UrlListEditor policy={policy} isDisabled={isDisabled} onChange={onPatch} />
          </FormSection>

          <FormSection title={_("Domains & regex")} titleElement="h3">
            <FormGroup label={_("Allow domains")} fieldId="ap-allow-domains">
              <ListEditor
                value={policy.allowDomains ?? []}
                isDisabled={isDisabled}
                onChange={(v) => onPatch({ allowDomains: v })}
                placeholder={_("e.g. example.com")}
              />
            </FormGroup>
            <FormGroup label={_("Block domains")} fieldId="ap-block-domains">
              <ListEditor
                value={policy.blockDomains ?? []}
                isDisabled={isDisabled}
                onChange={(v) => onPatch({ blockDomains: v })}
                placeholder={_("e.g. ads.example.com")}
              />
            </FormGroup>
            <FormGroup label={_("Allow regex")} fieldId="ap-allow-regex">
              <ListEditor
                value={policy.allowRegex ?? []}
                isDisabled={isDisabled}
                onChange={(v) => onPatch({ allowRegex: v })}
                placeholder={_("regex pattern")}
              />
            </FormGroup>
            <FormGroup label={_("Block regex")} fieldId="ap-block-regex">
              <ListEditor
                value={policy.blockRegex ?? []}
                isDisabled={isDisabled}
                onChange={(v) => onPatch({ blockRegex: v })}
                placeholder={_("regex pattern")}
              />
            </FormGroup>
          </FormSection>

          <FormSection title={_("Response")} titleElement="h3">
            <FormGroup
              label={_("Blocked-query response")}
              fieldId="ap-response"
              labelHelp={hint(
                _(
                  "NXDOMAIN answers blocked queries with a name error; blocking address answers with the addresses below.",
                ),
              )}
            >
              <FormSelect
                id="ap-response"
                value={responseType}
                isDisabled={isDisabled}
                onChange={(_e, v) => onPatch({ responseType: v as AccessPolicy["responseType"] })}
                aria-label={_("Blocked-query response")}
              >
                <FormSelectOption value="nxdomain" label={_("NXDOMAIN")} />
                <FormSelectOption value="blockingAddress" label={_("Blocking address")} />
              </FormSelect>
            </FormGroup>
            {responseType === "blockingAddress" && (
              <FormGroup
                label={_("Blocking addresses")}
                fieldId="ap-blocking"
                labelHelp={hint(
                  _(
                    "A/AAAA answers for blocked queries. With the block page enabled, blockingAddress policies land clients on the block page.",
                  ),
                )}
              >
                <ListEditor
                  value={policy.blockingAddresses ?? []}
                  isDisabled={isDisabled}
                  onChange={(v) => onPatch({ blockingAddresses: v })}
                  placeholder="0.0.0.0"
                />
              </FormGroup>
            )}
          </FormSection>

          <FormSection title={_("Assignments")} titleElement="h3">
            <FormGroup label={_("Networks")} fieldId="ap-networks" role="group">
              <Checkbox
                id="ap-net-lan"
                label={_("LAN")}
                isChecked={networks.includes("lan")}
                isDisabled={isDisabled}
                onChange={(_e, c) => toggleNetwork("lan", c)}
              />
              {guestEnabled ? (
                <Checkbox
                  id="ap-net-guest"
                  label={_("Guest")}
                  isChecked={networks.includes("guest")}
                  isDisabled={isDisabled}
                  onChange={(_e, c) => toggleNetwork("guest", c)}
                />
              ) : (
                <Tooltip content={_("The guest network is not enabled (Network page).")}>
                  <span>
                    <Checkbox id="ap-net-guest" label={_("Guest")} isChecked={false} isDisabled />
                  </span>
                </Tooltip>
              )}
              <Checkbox
                id="ap-net-wireguard"
                label={_("WireGuard")}
                isChecked={networks.includes("wireguard")}
                isDisabled={isDisabled}
                onChange={(_e, c) => toggleNetwork("wireguard", c)}
              />
            </FormGroup>
            <FormGroup label={_("Subnets (CIDR)")} fieldId="ap-subnets">
              <ListEditor
                value={assignments.subnets ?? []}
                isDisabled={isDisabled}
                onChange={(v) => patchAssignments({ subnets: v })}
                placeholder="10.48.5.0/28"
              />
            </FormGroup>
            <FormGroup label={_("Host groups")} fieldId="ap-hostgroups">
              <CheckboxMultiSelect
                options={hostGroupOptions}
                selected={assignments.hostGroups ?? []}
                isDisabled={isDisabled}
                onChange={(v) => patchAssignments({ hostGroups: v })}
                placeholder={_("Select host groups")}
              />
            </FormGroup>
            <FormGroup
              label={_("Directory groups")}
              fieldId="ap-dirgroups"
              labelHelp={hint(
                _(
                  "Devices assigned to a member of one of these directory groups get this policy. Type the group name exactly as the directory spells it — names are resolved on demand, so a group you have not used before will not autocomplete.",
                ),
              )}
            >
              <TypeaheadMultiSelect
                options={directoryGroupOptions}
                unresolved={directoryUnresolved}
                isCreatable
                selected={assignments.directoryGroups ?? []}
                isDisabled={isDisabled}
                onChange={(v) => patchAssignments({ directoryGroups: v })}
                placeholder={_("Type a directory group name")}
              />
            </FormGroup>
          </FormSection>
        </Form>
      </CardBody>
    </Card>
  );
};

// ── Policies tab ─────────────────────────────────────────────────────────────
const PoliciesTab = () => {
  const s = useSettings();
  const { state: directory, unresolved: directoryUnresolved } = useDirectory();
  const [editing, setEditing] = useState<number | null>(null);

  if (!s.ready && !s.error) {
    return <Loading />;
  }
  if (s.error) {
    return (
      <Alert variant="danger" isInline title={_("Could not load settings")}>
        {s.error}
      </Alert>
    );
  }

  const section = sectionOf(s);
  const policies = section.policies ?? [];
  const defaultPolicy = section.defaultPolicy ?? "Base";
  const locked = s.lockedOf("accessPolicies");
  const hostGroupOptions = s.valueOf<HostGroup[]>("hostGroups", []).map((g) => g.name);
  const guestEnabled = Boolean(s.valueOf("guest.enable", false));
  const names = policies.map((p) => p.name);

  const write = (sec: AccessPoliciesSection) => writeSection(s, sec);
  const updatePolicy = (index: number, patch: Partial<AccessPolicy>) => {
    const current = policies[index];
    if (!current) {
      return;
    }
    const next: AccessPoliciesSection = {
      ...section,
      policies: policies.map((p, i) => (i === index ? { ...p, ...patch } : p)),
    };
    // Renaming the default policy moves the default along with it.
    if (patch.name !== undefined && patch.name !== current.name && current.name === defaultPolicy) {
      next.defaultPolicy = patch.name;
    }
    write(next);
  };
  const addPolicy = () => {
    const name = uniqueName(_("New policy"), names);
    write({ ...section, policies: [...policies, emptyPolicy(name)] });
    setEditing(policies.length);
  };
  const duplicatePolicy = (index: number) => {
    const src = policies[index];
    if (!src) {
      return;
    }
    const copy = {
      ...structuredClone(src),
      name: uniqueName(cockpit.format(_("$0 copy"), src.name), names),
    };
    write({ ...section, policies: [...policies, copy] });
    setEditing(policies.length);
  };
  const deletePolicy = (index: number) => {
    write({ ...section, policies: policies.filter((_p, i) => i !== index) });
    setEditing((cur) => {
      if (cur === null || cur === index) {
        return null;
      }
      return cur > index ? cur - 1 : cur;
    });
  };

  const nameErrorFor = (index: number): string => {
    const p = policies[index];
    if (!p) {
      return "";
    }
    if (!p.name.trim()) {
      return _("Policy name must not be empty.");
    }
    if (policies.some((other, i) => i !== index && other.name === p.name)) {
      return _("Another policy already has this name.");
    }
    return "";
  };

  // Evaluation order: highest priority first (the resolver's within-tier order).
  const ordered = policies
    .map((policy, index) => ({ policy, index }))
    .toSorted((a, b) => (b.policy.priority ?? 0) - (a.policy.priority ?? 0));
  const editingPolicy = editing === null ? undefined : policies[editing];

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem>
        <Split hasGutter>
          <SplitItem isFilled>
            <div className="pf-v6-u-color-200">
              {_(
                "One policy wins per client: host group, then directory group, then subnet/network, then the default policy; within a tier the highest priority wins.",
              )}
            </div>
          </SplitItem>
          <SplitItem>
            <Button variant="primary" onClick={addPolicy} isDisabled={locked}>
              {_("Add policy")}
            </Button>
          </SplitItem>
        </Split>
      </StackItem>
      <StackItem isFilled style={{ overflowY: "auto" }}>
        <Stack hasGutter>
          <StackItem>
            {policies.length === 0 ? (
              <EmptyState>
                <EmptyStateBody>
                  {_(
                    'No policies defined — the backend synthesizes a "Base" policy until one is added.',
                  )}
                </EmptyStateBody>
              </EmptyState>
            ) : (
              <Table variant="compact" aria-label={_("Access policies")}>
                <Thead>
                  <Tr>
                    <Th>{_("Name")}</Th>
                    <Th>{_("Priority")}</Th>
                    <Th>{_("Filters")}</Th>
                    <Th>{_("Assignments")}</Th>
                    <Th screenReaderText={_("Actions")} />
                  </Tr>
                </Thead>
                <Tbody>
                  {ordered.map(({ policy, index }) => {
                    const isDefault = policy.name === defaultPolicy;
                    return (
                      <Tr key={index}>
                        <Td>
                          {policy.name}{" "}
                          {isDefault && (
                            <Label color="orange" isCompact>
                              {_("Default")}
                            </Label>
                          )}
                        </Td>
                        <Td>{policy.priority ?? 0}</Td>
                        <Td>
                          <FiltersSummary policy={policy} />
                        </Td>
                        <Td>
                          <AssignmentsSummary assignments={policy.assignments} />
                        </Td>
                        <Td modifier="fitContent">
                          <Button variant="link" isInline onClick={() => setEditing(index)}>
                            {_("Edit")}
                          </Button>{" "}
                          <Button
                            variant="link"
                            isInline
                            isDisabled={locked}
                            onClick={() => duplicatePolicy(index)}
                          >
                            {_("Duplicate")}
                          </Button>{" "}
                          {isDefault ? (
                            <Tooltip
                              content={_(
                                "The default policy cannot be deleted — make another policy the default first.",
                              )}
                            >
                              <Button variant="link" isInline isDanger isAriaDisabled>
                                {_("Delete")}
                              </Button>
                            </Tooltip>
                          ) : (
                            <Button
                              variant="link"
                              isInline
                              isDanger
                              isDisabled={locked}
                              onClick={() => deletePolicy(index)}
                            >
                              {_("Delete")}
                            </Button>
                          )}
                        </Td>
                      </Tr>
                    );
                  })}
                </Tbody>
              </Table>
            )}
          </StackItem>
          {editing !== null && editingPolicy && (
            <StackItem>
              <PolicyEditorCard
                policy={editingPolicy}
                nameError={nameErrorFor(editing)}
                isDefault={editingPolicy.name === defaultPolicy}
                guestEnabled={guestEnabled}
                hostGroupOptions={hostGroupOptions}
                directoryGroupOptions={directory ? directory.groups.map((g) => g.name) : []}
                directoryUnresolved={directoryUnresolved}
                isDisabled={locked}
                onPatch={(patch) => updatePolicy(editing, patch)}
                onMakeDefault={() => write({ ...section, defaultPolicy: editingPolicy.name })}
                onClose={() => setEditing(null)}
              />
            </StackItem>
          )}
        </Stack>
      </StackItem>
      <StackItem>
        <SaveBar saving={s.saving} status={s.status} onSave={s.save} onSaveApply={s.saveAndApply} />
      </StackItem>
    </Stack>
  );
};

// ── Preview tab ──────────────────────────────────────────────────────────────
const TIER_LABELS: Record<MatchStep["tier"], string> = {
  hostGroup: "Host group",
  directoryGroup: "Directory group",
  subnet: "Subnet",
  network: "Network / subnet",
  default: "Default policy",
};

const PreviewTab = () => {
  const s = useSettings();
  const { state: directory, unresolved: directoryUnresolved } = useDirectory();
  const [mode, setMode] = useState("device");
  const [device, setDevice] = useState("");
  const [ip, setIp] = useState("");
  const [userRef, setUserRef] = useState("");

  if (!s.ready && !s.error) {
    return <Loading />;
  }
  if (s.error) {
    return (
      <Alert variant="danger" isInline title={_("Could not load settings")}>
        {s.error}
      </Alert>
    );
  }

  const hosts = s.valueOf<RouterHost[]>("hosts", []);
  const section = sectionOf(s);
  const cidrs = networkCidrs(s);
  const selectedHost = hosts.find((h) => h.name === device);
  const input =
    mode === "device"
      ? selectedHost
        ? { host: selectedHost }
        : null
      : mode === "ip"
        ? ip.trim()
          ? { ip: ip.trim() }
          : null
        : userRef
          ? { userId: userRef }
          : null;
  const result = input ? resolvePolicy(input, section, cidrs, directory, hosts) : null;

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem>
        <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
          <FormGroup label={_("Look up by")} fieldId="pv-mode">
            <FormSelect
              id="pv-mode"
              value={mode}
              onChange={(_e, v) => setMode(v)}
              aria-label={_("Look up by")}
              style={{ maxWidth: "20rem" }}
            >
              <FormSelectOption value="device" label={_("Registered device")} />
              <FormSelectOption value="ip" label={_("IP address")} />
              <FormSelectOption value="user" label={_("Directory user")} />
            </FormSelect>
          </FormGroup>
          {mode === "device" && (
            <FormGroup label={_("Device")} fieldId="pv-device">
              <FormSelect
                id="pv-device"
                value={device}
                onChange={(_e, v) => setDevice(v)}
                aria-label={_("Device")}
                style={{ maxWidth: "20rem" }}
              >
                <FormSelectOption value="" label={_("Select a device…")} />
                {hosts.map((h) => (
                  <FormSelectOption key={h.mac} value={h.name} label={h.name} />
                ))}
              </FormSelect>
            </FormGroup>
          )}
          {mode === "ip" && (
            <FormGroup label={_("IP address")} fieldId="pv-ip">
              <TextInput
                id="pv-ip"
                value={ip}
                onChange={(_e, v) => setIp(v)}
                placeholder="10.48.4.20"
                style={{ maxWidth: "20rem" }}
              />
            </FormGroup>
          )}
          {mode === "user" && (
            <FormGroup label={_("User")} fieldId="pv-user">
              {/* Free text with a datalist rather than a closed select: SSSD is
                  never enumerated, so `directory.users` only holds identities
                  already referenced and resolved. A closed list could not
                  preview a user who has not been assigned to a device yet. */}
              <TextInput
                id="pv-user"
                value={userRef}
                onChange={(_e, v) => setUserRef(v)}
                placeholder={_("directory login name, e.g. jdoe")}
                list="pv-user-options"
                style={{ maxWidth: "20rem" }}
              />
              <datalist id="pv-user-options">
                {(directory?.users ?? []).map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.name && u.name !== u.id ? u.name : u.id}
                  </option>
                ))}
              </datalist>
              {userRef.trim() !== "" &&
                directoryUnresolved.some(
                  (n) => n.toLowerCase() === userRef.trim().toLowerCase(),
                ) && (
                  <div
                    className="pf-v6-u-color-200"
                    style={{ fontSize: "0.85rem", marginBlockStart: "0.25rem" }}
                  >
                    {_(
                      "The last directory sync could not resolve this name — the user tier will not match.",
                    )}
                  </div>
                )}
            </FormGroup>
          )}
        </Form>
      </StackItem>
      <StackItem isFilled style={{ overflowY: "auto" }}>
        {result ? (
          <Card isCompact>
            <CardTitle>{_("Resolution chain")}</CardTitle>
            <CardBody>
              <Table variant="compact" aria-label={_("Policy resolution chain")}>
                <Thead>
                  <Tr>
                    <Th>{_("#")}</Th>
                    <Th>{_("Tier")}</Th>
                    <Th>{_("Detail")}</Th>
                    <Th>{_("Policy")}</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {result.chain.map((step, i) => (
                    <Tr
                      key={i}
                      style={step.won ? { background: "rgba(62, 134, 53, 0.12)" } : undefined}
                    >
                      <Td>{i + 1}</Td>
                      <Td>
                        {_(TIER_LABELS[step.tier])}{" "}
                        {step.won && (
                          <Label color="green" isCompact>
                            {_("winner")}
                          </Label>
                        )}
                      </Td>
                      <Td>{step.detail}</Td>
                      <Td>
                        {step.policy ? (
                          <Label color={step.won ? "green" : "grey"} isCompact>
                            {step.policy}
                          </Label>
                        ) : (
                          "—"
                        )}
                      </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
              <div style={{ marginBlockStart: "0.75rem", fontWeight: 600 }}>
                {result.policy
                  ? cockpit.format(_('Client would get policy "$0".'), result.policy)
                  : _("No policy matches — the client would get no filtering group.")}
              </div>
            </CardBody>
          </Card>
        ) : (
          <EmptyState>
            <EmptyStateBody>
              {_("Pick a device, enter an IP, or pick a user to preview the winning policy.")}
            </EmptyStateBody>
          </EmptyState>
        )}
      </StackItem>
    </Stack>
  );
};

// ── DNS settings tab ─────────────────────────────────────────────────────────
const DnsSettingsTab = () => {
  const s = useSettings();

  if (!s.ready && !s.error) {
    return <Loading />;
  }
  if (s.error) {
    return (
      <Alert variant="danger" isInline title={_("Could not load settings")}>
        {s.error}
      </Alert>
    );
  }

  const portInput = (path: string, fallback: number, ariaLabel: string) => {
    const value = s.valueOf<number>(path, fallback);
    const set = (raw: number) => {
      const clamped = Math.min(65_535, Math.max(0, Math.trunc(raw)));
      s.setLeaf(path, clamped);
    };
    return (
      <NumberInput
        value={value}
        min={0}
        max={65_535}
        isDisabled={s.lockedOf(path)}
        widthChars={6}
        onMinus={() => set(value - 1)}
        onPlus={() => set(value + 1)}
        onChange={(e) => {
          const n = Number((e.target as HTMLInputElement).value);
          if (Number.isFinite(n)) {
            set(n);
          }
        }}
        inputAriaLabel={ariaLabel}
      />
    );
  };

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem isFilled style={{ overflowY: "auto" }}>
        <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
          <FormSection title={_("Upstream DNS")} titleElement="h2">
            <FormGroup label={_("Upstream servers")} fieldId="dns-upstream">
              <ListEditor
                value={s.valueOf("dns.technitium.upstreamServers", [])}
                isDisabled={s.lockedOf("dns.technitium.upstreamServers")}
                onChange={(v) => s.setLeaf("dns.technitium.upstreamServers", v)}
                placeholder={_("https://dns.example/dns-query")}
              />
            </FormGroup>
          </FormSection>

          <FormSection title={_("Ports")} titleElement="h2">
            <FormGroup label={_("DNS listen port")} fieldId="dns-listen">
              {portInput("dns.technitium.listenPort", 53, _("DNS listen port"))}
            </FormGroup>
            <FormGroup label={_("Web console port")} fieldId="dns-web">
              {portInput("dns.technitium.webPort", 5380, _("Web console port"))}
            </FormGroup>
          </FormSection>

          <FormSection title={_("Protection")} titleElement="h2">
            <FormGroup
              label={_("Enforce SafeSearch")}
              fieldId="dns-safesearch"
              labelHelp={hint(
                _("Enforced via DNS records for Google, Bing, DuckDuckGo, and YouTube."),
              )}
            >
              <Switch
                id="dns-safesearch"
                isChecked={Boolean(s.valueOf("dns.technitium.safeSearch", false))}
                isDisabled={s.lockedOf("dns.technitium.safeSearch")}
                onChange={(_e, c) => s.setLeaf("dns.technitium.safeSearch", c)}
                aria-label={_("Enforce SafeSearch")}
              />
            </FormGroup>
            <FormGroup
              label={_("Block DoH providers")}
              fieldId="dns-doh"
              labelHelp={hint(
                _(
                  "Block public DNS-over-HTTPS resolver domains in every policy so clients cannot bypass filtering.",
                ),
              )}
            >
              <Switch
                id="dns-doh"
                isChecked={Boolean(s.valueOf("dns.technitium.blockDoHProviders", true))}
                isDisabled={s.lockedOf("dns.technitium.blockDoHProviders")}
                onChange={(_e, c) => s.setLeaf("dns.technitium.blockDoHProviders", c)}
                aria-label={_("Block DoH providers")}
              />
            </FormGroup>
          </FormSection>

          <FormSection title={_("Block page")} titleElement="h2">
            <FormGroup
              label={_("Serve a block page")}
              fieldId="bp-enable"
              labelHelp={hint(
                _(
                  "Served on ports 80/443 for blocked domains; includes the exception-request form.",
                ),
              )}
            >
              <Switch
                id="bp-enable"
                isChecked={Boolean(s.valueOf("accessPolicies.blockPage.enable", false))}
                isDisabled={s.lockedOf("accessPolicies.blockPage.enable")}
                onChange={(_e, c) => s.setLeaf("accessPolicies.blockPage.enable", c)}
                aria-label={_("Serve a block page")}
              />
            </FormGroup>
            <FormGroup label={_("Browser title")} fieldId="bp-title">
              <TextInput
                id="bp-title"
                value={s.valueOf("accessPolicies.blockPage.title", "Website Blocked")}
                isDisabled={s.lockedOf("accessPolicies.blockPage.title")}
                onChange={(_e, v) => s.setLeaf("accessPolicies.blockPage.title", v)}
              />
            </FormGroup>
            <FormGroup label={_("Heading")} fieldId="bp-heading">
              <TextInput
                id="bp-heading"
                value={s.valueOf("accessPolicies.blockPage.heading", "Website Blocked")}
                isDisabled={s.lockedOf("accessPolicies.blockPage.heading")}
                onChange={(_e, v) => s.setLeaf("accessPolicies.blockPage.heading", v)}
              />
            </FormGroup>
            <FormGroup label={_("Message")} fieldId="bp-message">
              <TextArea
                id="bp-message"
                value={s.valueOf(
                  "accessPolicies.blockPage.message",
                  "This website has been blocked by your network administrator.",
                )}
                isDisabled={s.lockedOf("accessPolicies.blockPage.message")}
                onChange={(_e, v) => s.setLeaf("accessPolicies.blockPage.message", v)}
                rows={4}
                resizeOrientation="vertical"
                aria-label={_("Block page message")}
              />
            </FormGroup>
            <FormGroup label={_("Contact email")} fieldId="bp-contact">
              <TextInput
                id="bp-contact"
                type="email"
                value={s.valueOf("accessPolicies.blockPage.contactEmail", "")}
                isDisabled={s.lockedOf("accessPolicies.blockPage.contactEmail")}
                onChange={(_e, v) => s.setLeaf("accessPolicies.blockPage.contactEmail", v)}
              />
            </FormGroup>
          </FormSection>

          <SaveBar
            saving={s.saving}
            status={s.status}
            onSave={s.save}
            onSaveApply={s.saveAndApply}
          />
        </Form>
      </StackItem>
    </Stack>
  );
};

// ── Exception requests tab ───────────────────────────────────────────────────
const statusColor = (st: ExceptionRequest["status"]): "orange" | "green" | "red" =>
  st === "pending" ? "orange" : st === "approved" ? "green" : "red";

const requesterOf = (r: ExceptionRequest): string => r.device ?? r.user ?? r.client_ip;

const ExceptionsTab = ({
  requests,
  error,
  onReload,
}: {
  requests: ExceptionRequest[] | null;
  error: string;
  onReload: () => void;
}) => {
  const s = useSettings();
  const [approving, setApproving] = useState<ExceptionRequest | null>(null);
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionStatus, setActionStatus] = useState<{ ok: boolean; msg: string } | null>(null);

  if ((!s.ready && !s.error) || (requests === null && !error)) {
    return <Loading />;
  }

  const section = sectionOf(s);
  const policies = section.policies ?? [];

  const startApprove = (req: ExceptionRequest) => {
    setActionStatus(null);
    setApproving(req);
    // Default target: the policy that blocked the request, when it still exists.
    const candidates = [req.policy, section.defaultPolicy, policies[0]?.name];
    const found = candidates.find((c) => Boolean(c) && policies.some((p) => p.name === c));
    setTarget(found ?? "");
  };

  const approve = () => {
    if (!approving || !target) {
      return;
    }
    const req = approving;
    setBusy(true);
    setActionStatus(null);
    const next: AccessPoliciesSection = {
      ...section,
      policies: policies.map((p) =>
        p.name === target && !(p.allowDomains ?? []).includes(req.domain)
          ? { ...p, allowDomains: [...(p.allowDomains ?? []), req.domain] }
          : p,
      ),
    };
    // Persist the settings JSON directly (the working-copy save would race the
    // state update); the user still applies the change from the tray.
    writeDesired(setPath(s.desired, "accessPolicies", next as unknown as Json))
      .then(() => setExceptionStatus(req.id, "approved"))
      .then(() => {
        setActionStatus({
          ok: true,
          msg: cockpit.format(
            _('$0 allowed in policy "$1" — apply the change from the tray to activate it.'),
            req.domain,
            target,
          ),
        });
        setApproving(null);
        s.reload();
        onReload();
      })
      .catch((e: unknown) => setActionStatus({ ok: false, msg: errMsg(e) }))
      .finally(() => setBusy(false));
  };

  const deny = (req: ExceptionRequest) => {
    setBusy(true);
    setActionStatus(null);
    setExceptionStatus(req.id, "denied")
      .then(() => onReload())
      .catch((e: unknown) => setActionStatus({ ok: false, msg: errMsg(e) }))
      .finally(() => setBusy(false));
  };

  const rows = requests ?? [];

  return (
    <Stack hasGutter className="ct-router-stack">
      <StackItem>
        <Split hasGutter>
          <SplitItem isFilled>
            <div className="pf-v6-u-color-200">
              {_("Requests submitted through the block page's exception-request form.")}
            </div>
          </SplitItem>
          <SplitItem>
            <Button variant="secondary" onClick={onReload}>
              {_("Refresh")}
            </Button>
          </SplitItem>
        </Split>
      </StackItem>
      {error && (
        <StackItem>
          <Alert variant="danger" title={_("Could not reach router-logd")} isInline>
            {error}
          </Alert>
        </StackItem>
      )}
      {actionStatus && (
        <StackItem>
          <Alert
            variant={actionStatus.ok ? "success" : "danger"}
            isInline
            title={actionStatus.ok ? _("Exception approved") : _("Could not update the request")}
          >
            {actionStatus.msg}
          </Alert>
        </StackItem>
      )}
      {approving && (
        <StackItem>
          <Card isCompact>
            <CardTitle>{cockpit.format(_("Approve exception for $0"), approving.domain)}</CardTitle>
            <CardBody>
              <Form isHorizontal onSubmit={(e) => e.preventDefault()}>
                <FormGroup
                  label={_("Add allow rule to policy")}
                  fieldId="ex-policy"
                  labelHelp={hint(_("The domain is appended to the policy's allow-domains list."))}
                >
                  <FormSelect
                    id="ex-policy"
                    value={target}
                    onChange={(_e, v) => setTarget(v)}
                    aria-label={_("Target policy")}
                    style={{ maxWidth: "20rem" }}
                  >
                    {policies.map((p) => (
                      <FormSelectOption key={p.name} value={p.name} label={p.name} />
                    ))}
                  </FormSelect>
                </FormGroup>
                <Split hasGutter>
                  <SplitItem>
                    <Button
                      variant="primary"
                      onClick={approve}
                      isLoading={busy}
                      isDisabled={busy || !target}
                    >
                      {_("Approve")}
                    </Button>
                  </SplitItem>
                  <SplitItem>
                    <Button variant="link" onClick={() => setApproving(null)} isDisabled={busy}>
                      {_("Cancel")}
                    </Button>
                  </SplitItem>
                </Split>
              </Form>
            </CardBody>
          </Card>
        </StackItem>
      )}
      <StackItem isFilled className="ct-table-scroll">
        {rows.length === 0 ? (
          <EmptyState>
            <EmptyStateBody>{_("No exception requests.")}</EmptyStateBody>
          </EmptyState>
        ) : (
          <Table variant="compact" aria-label={_("Exception requests")}>
            <Thead>
              <Tr>
                <Th>{_("Time")}</Th>
                <Th>{_("Domain")}</Th>
                <Th>{_("Requested by")}</Th>
                <Th>{_("Group")}</Th>
                <Th>{_("Policy")}</Th>
                <Th>{_("Reason")}</Th>
                <Th>{_("Status")}</Th>
                <Th screenReaderText={_("Actions")} />
              </Tr>
            </Thead>
            <Tbody>
              {rows.map((r) => (
                <Tr key={r.id}>
                  <Td>{fmtTime(r.ts)}</Td>
                  <Td>{r.domain}</Td>
                  <Td>
                    {requesterOf(r)}
                    {(r.device !== null || r.user !== null) && (
                      <div className="pf-v6-u-color-200" style={{ fontSize: "0.8rem" }}>
                        {r.device && r.user ? `${r.user} · ${r.client_ip}` : r.client_ip}
                      </div>
                    )}
                  </Td>
                  <Td>{r.host_group ?? "—"}</Td>
                  <Td>{r.policy ?? "—"}</Td>
                  <Td modifier="truncate" style={{ maxWidth: "16rem" }}>
                    {r.reason ? (
                      <Tooltip content={r.reason}>
                        <span>{r.reason}</span>
                      </Tooltip>
                    ) : (
                      "—"
                    )}
                  </Td>
                  <Td>
                    <Label color={statusColor(r.status)} isCompact>
                      {r.status}
                    </Label>
                  </Td>
                  <Td modifier="fitContent">
                    {r.status === "pending" ? (
                      <>
                        <Button
                          variant="link"
                          isInline
                          isDisabled={busy}
                          onClick={() => startApprove(r)}
                        >
                          {_("Approve")}
                        </Button>{" "}
                        <Button
                          variant="link"
                          isInline
                          isDanger
                          isDisabled={busy}
                          onClick={() => deny(r)}
                        >
                          {_("Deny")}
                        </Button>
                      </>
                    ) : (
                      "—"
                    )}
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
      </StackItem>
    </Stack>
  );
};

// ── page shell ───────────────────────────────────────────────────────────────
export const AccessPolicies = () => {
  const [tab, setTab] = useState("policies");
  const [requests, setRequests] = useState<ExceptionRequest[] | null>(null);
  const [requestsError, setRequestsError] = useState("");

  const loadRequests = useCallback(() => {
    setRequestsError("");
    void exceptionRequests()
      .then((r) => setRequests(r))
      .catch((e: unknown) => {
        setRequests([]);
        setRequestsError(errMsg(e));
      });
  }, []);
  useEffect(() => {
    loadRequests();
  }, [loadRequests]);

  const pending = (requests ?? []).filter((r) => r.status === "pending").length;
  const exceptionsLabel =
    pending > 0 ? cockpit.format(_("Exception requests ($0)"), pending) : _("Exception requests");

  return (
    <TabbedPage
      subnav={
        <SubNav
          active={tab}
          onSelect={setTab}
          items={[
            { id: "policies", label: _("Policies") },
            { id: "preview", label: _("Preview") },
            { id: "dns", label: _("DNS settings") },
            { id: "exceptions", label: exceptionsLabel },
          ]}
        />
      }
    >
      {tab === "policies" && <PoliciesTab />}
      {tab === "preview" && <PreviewTab />}
      {tab === "dns" && <DnsSettingsTab />}
      {tab === "exceptions" && (
        <ExceptionsTab requests={requests} error={requestsError} onReload={loadRequests} />
      )}
    </TabbedPage>
  );
};
