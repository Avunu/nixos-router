// Reusable building blocks for the Settings tabs and config pages: the native
// Cockpit sub-nav, a string-list editor, save-status, and the `useSettings` hook
// that loads the JSON config and tracks a working copy for the forms.
import { useState, useEffect, useCallback, useRef } from "react";
import type { ReactNode } from "react";
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
  Popover,
  PageSection,
} from "@patternfly/react-core";
import { HelpIcon } from "@patternfly/react-icons";
import {
  loadState,
  writeDesired,
  getPath,
  setPath,
  isLocked,
  errMsg,
  rebaseEdits,
  onAdminChange,
} from "./nix";
import type { SettingsState, Json } from "./nix";

const _ = cockpit.gettext;

// PatternFly's FormGroup `labelHelp` expects a ReactElement (a popover trigger);
// wrap a help string into one.
export const hint = (body: string) => (
  <Popover bodyContent={body}>
    <button
      type="button"
      aria-label={_("More information")}
      onClick={(e) => e.preventDefault()}
      className="pf-v6-c-form__group-label-help"
    >
      <HelpIcon />
    </button>
  </Popover>
);

// Horizontal sub-navigation matching Cockpit's own page pattern (see
// pkgs/systemd/service-tabs.tsx): a `Nav variant="horizontal-subnav"` of link
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

// Page layout mirroring Cockpit's native subnav pattern (see pkgs/systemd/
// services.jsx): the SubNav sits in its own hasBodyWrapper={false} section
// (minimal space above the tabs), and the content sits in a separate filled
// section below — the gap between tabs and content is that section's padding.
export const TabbedPage = ({
  header,
  subnav,
  fills = true,
  children,
}: {
  // Content shown ABOVE the tabs, in its own section. It needs one: PatternFly's
  // `horizontal-subnav` Nav manages its own height and horizontal overflow and
  // expects to be the only thing in its section — putting a banner beside it
  // collapses the nav and clips the tab labels.
  header?: ReactNode;
  subnav?: ReactNode;
  fills?: boolean;
  children: ReactNode;
}) => (
  <>
    {header ? <PageSection hasBodyWrapper={false}>{header}</PageSection> : null}
    {subnav ? (
      <PageSection hasBodyWrapper={false} className="ct-router-subnav">
        {subnav}
      </PageSection>
    ) : null}
    <PageSection isFilled={fills} className={fills ? "ct-router-body" : undefined}>
      {children}
    </PageSection>
  </>
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
//
// The working copy follows the file. Every write of the settings file
// (writeDesired) and every apply announces itself with "router:changed", and
// the hook then rebuilds its copy from disk rather than keeping the one it
// loaded — otherwise a page left open across the changes tray's Revert, or
// another form's save, would write its stale copy straight back over them.
// Edits the admin has not saved yet survive the rebuild (see rebaseEdits).
//
// A settings file that cannot be read (root-only, in a session with Limited
// access) is an `error`, never an empty form: `ready` stays false, so pages
// show the message instead of a form and a Save button, and writeDesired
// refuses anyway without a loaded state. Switching administrative access on or
// off reloads, since it changes what can be read.
export function useSettings() {
  const [state, setState] = useState<SettingsState | null>(null);
  const [desired, setDesired] = useState<Json>({});
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState<{ ok: boolean; msg: string } | null>(null);
  // Unsaved edits, leaf path → value, in the order they were last made.
  const pending = useRef(new Map<string, Json>());

  const reload = useCallback(() => {
    loadState()
      .then((s) => {
        setState(s);
        setError("");
        setDesired(rebaseEdits(s.desired, pending.current));
      })
      .catch((e: unknown) => {
        // Drop a copy loaded earlier too, so no form outlives a failed read.
        setState(null);
        setError(errMsg(e));
      });
  }, []);
  useEffect(() => {
    reload();
    window.addEventListener("router:changed", reload);
    const offAdmin = onAdminChange(reload);
    return () => {
      window.removeEventListener("router:changed", reload);
      offAdmin();
    };
  }, [reload]);

  const setLeaf = useCallback((path: string, val: Json) => {
    // Delete first so a repeated edit moves to the end: re-applying in order
    // then lets a later edit of a parent path win over an earlier child one.
    pending.current.delete(path);
    pending.current.set(path, val);
    setDesired((d) => setPath(d, path, val));
  }, []);

  // Form value: the working desired value, falling back to the effective value
  // (defaults / Nix-locked) when the JSON doesn't set this path. The fallback's
  // type drives T; the JSON store is the (unavoidable) dynamic boundary.
  const valueOf = useCallback(
    <T,>(path: string, fallback: T): T => {
      const v = getPath(desired, path);
      if (v !== undefined) {
        return v as unknown as T;
      }
      const e = state ? getPath(state.effective, path) : undefined;
      return (e !== undefined ? e : fallback) as unknown as T;
    },
    [desired, state],
  );

  const lockedOf = useCallback((path: string) => (state ? isLocked(state, path) : false), [state]);

  const persist = useCallback(
    (apply: boolean) => {
      setSaving(true);
      setStatus(null);
      return writeDesired(desired, state)
        .then(() => {
          setStatus({
            ok: true,
            msg: apply ? _("Saved — applying…") : _("Saved. Apply to take effect."),
          });
          if (apply) {
            window.dispatchEvent(new Event("router:apply"));
          }
        })
        .catch((e: unknown) => setStatus({ ok: false, msg: errMsg(e) }))
        .finally(() => setSaving(false));
    },
    [desired, state],
  );

  // Replace the whole settings file with `obj`, built from `desired`, for a
  // page that writes outside the working copy. Refused like `save` when the
  // settings were not read.
  const write = useCallback((obj: Json) => writeDesired(obj, state), [state]);

  return {
    ready: Boolean(state),
    error,
    desired,
    effective: state?.effective ?? {},
    setLeaf,
    valueOf,
    lockedOf,
    save: () => persist(false),
    saveAndApply: () => persist(true),
    write,
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
  applyDisabled,
}: {
  saving: boolean;
  status: { ok: boolean; msg: string } | null;
  onSave: () => void;
  onSaveApply: () => void;
  applyDisabled?: boolean;
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
        <Button variant="primary" onClick={onSaveApply} isDisabled={saving || applyDisabled}>
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
    if (v && !value.includes(v)) {
      onChange([...value, v]);
    }
    setDraft("");
  };
  return (
    <Split hasGutter>
      <SplitItem isFilled>
        {value.length > 0 && (
          <LabelGroup numLabels={20} isEditable={false} style={{ marginBlockEnd: "0.5rem" }}>
            {value.map((item) => (
              <Label
                key={item}
                onClose={isDisabled ? undefined : () => onChange(value.filter((x) => x !== item))}
              >
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
