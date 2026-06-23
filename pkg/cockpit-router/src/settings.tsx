// Reusable building blocks for the Settings tabs and config pages: the native
// Cockpit sub-nav, a string-list editor, save-status, and the `useSettings` hook
// that loads the JSON config and tracks a working copy for the forms.
import { useState, useEffect, useCallback } from "react";
import {
  Alert,
  Button,
  TextInput,
  Label,
  LabelGroup,
  Spinner,
  Split,
  SplitItem,
  Nav,
  NavList,
  NavItem,
} from "@patternfly/react-core";
import { loadState, writeDesired, getPath, setPath, isLocked, type SettingsState, type Json } from "./nix";

const _ = cockpit.gettext;

// Horizontal sub-navigation matching Cockpit's own page pattern (see
// pkg/systemd/service-tabs.tsx): a `Nav variant="horizontal-subnav"` of link
// buttons rather than PatternFly Tabs, so the router pages look native.
export const SubNav = ({
  items,
  active,
  onSelect,
}: {
  items: { id: string; label: string }[];
  active: string;
  onSelect: (id: string) => void;
}) => (
  <Nav variant="horizontal-subnav" onSelect={(_e, result) => onSelect(result.itemId as string)}>
    <NavList>
      {items.map((it) => (
        <NavItem key={it.id} itemId={it.id} preventDefault isActive={active === it.id}>
          <Button variant="link" component="a">
            {it.label}
          </Button>
        </NavItem>
      ))}
    </NavList>
  </Nav>
);

export const Loading = () => <Spinner />;

export const SaverStatus = ({ status }: { status: { ok: boolean; msg: string } | null }) =>
  status ? (
    <Alert
      variant={status.ok ? "success" : "danger"}
      isInline
      title={status.ok ? _("Settings saved") : _("Could not save settings")}
    >
      {status.msg}
    </Alert>
  ) : null;

// Loads the JSON config + effective/applied companions and exposes a working
// copy of `desired` that forms edit by leaf path. `save()` writes the JSON;
// `saveAndApply()` writes it then asks the changes tray to rebuild.
export function useSettings() {
  const [state, setState] = useState<SettingsState | null>(null);
  const [desired, setDesired] = useState<Json>({});
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState<{ ok: boolean; msg: string } | null>(null);

  const reload = useCallback(() => {
    loadState()
      .then((s) => {
        setState(s);
        setDesired(s.desired || {});
      })
      .catch((e: any) => setError(e.message || String(e)));
  }, []);
  useEffect(() => {
    reload();
  }, [reload]);

  const setLeaf = useCallback((path: string, val: any) => {
    setDesired((d) => setPath(d, path, val));
  }, []);

  // Form value: the working desired value, falling back to the effective value
  // (defaults / Nix-locked) when the JSON doesn't set this path.
  const valueOf = useCallback(
    (path: string, fallback?: any) => {
      const v = getPath(desired, path);
      if (v !== undefined) return v;
      const e = state ? getPath(state.effective, path) : undefined;
      return e !== undefined ? e : fallback;
    },
    [desired, state],
  );

  const lockedOf = useCallback((path: string) => (state ? isLocked(state, path) : false), [state]);

  const persist = useCallback(
    (apply: boolean) => {
      setSaving(true);
      setStatus(null);
      return writeDesired(desired)
        .then(() => {
          setStatus({ ok: true, msg: apply ? _("Saved — applying…") : _("Saved. Apply to take effect.") });
          if (apply) window.dispatchEvent(new Event("router:apply"));
        })
        .catch((e: any) => setStatus({ ok: false, msg: e.message || String(e) }))
        .finally(() => setSaving(false));
    },
    [desired],
  );

  return {
    ready: !!state,
    error,
    desired,
    effective: state?.effective ?? {},
    setLeaf,
    valueOf,
    lockedOf,
    save: () => persist(false),
    saveAndApply: () => persist(true),
    saving,
    status,
    reload,
  };
}

// Save / Save & Apply buttons + status, shared by every settings form.
export const SaveBar = ({
  saving,
  status,
  onSave,
  onSaveApply,
}: {
  saving: boolean;
  status: { ok: boolean; msg: string } | null;
  onSave: () => void;
  onSaveApply: () => void;
}) => (
  <>
    <SaverStatus status={status} />
    <Split hasGutter>
      <SplitItem>
        <Button variant="secondary" onClick={onSave} isLoading={saving} isDisabled={saving}>
          {_("Save")}
        </Button>
      </SplitItem>
      <SplitItem>
        <Button variant="primary" onClick={onSaveApply} isDisabled={saving}>
          {_("Save & apply")}
        </Button>
      </SplitItem>
    </Split>
  </>
);

// Edit a list of strings (allow/block lists, DNS upstreams, UT Capitole
// categories, …) as removable chips plus an add field.
export const ListEditor = ({
  value,
  onChange,
  placeholder,
  isDisabled,
}: {
  value: string[];
  onChange: (v: string[]) => void;
  placeholder?: string;
  isDisabled?: boolean;
}) => {
  const [draft, setDraft] = useState("");
  const add = () => {
    const v = draft.trim();
    if (v && !value.includes(v)) onChange([...value, v]);
    setDraft("");
  };
  return (
    <Split hasGutter>
      <SplitItem isFilled>
        {value.length > 0 && (
          <LabelGroup numLabels={20} isEditable={false} style={{ marginBlockEnd: "0.5rem" }}>
            {value.map((item) => (
              <Label key={item} onClose={isDisabled ? undefined : () => onChange(value.filter((x) => x !== item))}>
                {item}
              </Label>
            ))}
          </LabelGroup>
        )}
        {!isDisabled && (
          <Split hasGutter>
            <SplitItem isFilled>
              <TextInput
                value={draft}
                type="text"
                aria-label={placeholder || _("New entry")}
                placeholder={placeholder}
                onChange={(_e, v) => setDraft(v)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    add();
                  }
                }}
              />
            </SplitItem>
            <SplitItem>
              <Button variant="secondary" onClick={add} isDisabled={!draft.trim()}>
                {_("Add")}
              </Button>
            </SplitItem>
          </Split>
        )}
      </SplitItem>
    </Split>
  );
};
