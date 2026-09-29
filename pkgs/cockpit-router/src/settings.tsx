// Reusable building blocks for the Settings tabs and config pages: the native
// Cockpit sub-nav (with the tab in the page's URL), the page layout with its
// pinned save footer, a string-list editor, and the `usePageSettings` hook
// that tracks a page's working copy of the JSON config.
import {
  createContext,
  useState,
  useEffect,
  useCallback,
  useContext,
  useMemo,
  useRef,
} from "react";
import type { ReactNode } from "react";
import {
  Button,
  TextInput,
  Label,
  LabelGroup,
  Spinner,
  Split,
  SplitItem,
  Stack,
  StackItem,
  Nav,
  NavList,
  NavItem,
  Popover,
  PageSection,
} from "@patternfly/react-core";
import { HelpIcon } from "@patternfly/react-icons";
import { getPath, setPath, isLocked, errMsg, rebaseEdits, deepEqual } from "./nix";
import type { Json } from "./nix";
import { patchWithEdits } from "./settings-json";
import { NOT_LOADED } from "./settings-read";
import {
  SettingsConflictError,
  getRouterState,
  settingsChanged,
  subscribeRouterState,
  writeSettings,
} from "./router-state";
import type { LoadedSettings } from "./router-state";
import { usePageStatus } from "./page-status";

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

// The page's tab, kept in its URL (`#/?tab=<id>`) the way Cockpit's Services
// page keeps its own (pkg/systemd/services.jsx), so a link can open a tab —
// the changes panel links each saved change to the tab that edits it — and
// Back returns to the previous one. `tabs` are the valid ids (best declared
// once, outside the component), the first being the default.
function tabOf(tabs: readonly string[]): string {
  const { tab } = cockpit.location.options;
  if (typeof tab === "string" && tabs.includes(tab)) {
    return tab;
  }
  return tabs[0] ?? "";
}

export function useTabRoute(tabs: readonly string[]): [string, (tab: string) => void] {
  const [tab, setTab] = useState(() => tabOf(tabs));
  useEffect(() => {
    const onLocation = () => setTab(tabOf(tabs));
    cockpit.addEventListener("locationchanged", onLocation);
    return () => cockpit.removeEventListener("locationchanged", onLocation);
  }, [tabs]);
  const select = useCallback((next: string) => {
    const { path, options } = cockpit.location;
    const kept = Object.fromEntries(
      Object.entries(options).filter((e): e is [string, string] => typeof e[1] === "string"),
    );
    cockpit.location.go(path, { ...kept, tab: next });
    setTab(next);
  }, []);
  return [tab, select];
}

// Page layout mirroring Cockpit's native subnav pattern (see pkgs/systemd/
// services.jsx): the SubNav sits in its own hasBodyWrapper={false} section
// (minimal space above the tabs), and the content sits in a separate filled
// section below — the gap between tabs and content is that section's padding.
// A `footer` (the page's SaveActions) is pinned below the content, which
// scrolls above it, so saving never means scrolling to the end of a form.
export const TabbedPage = ({
  header,
  subnav,
  fills = true,
  footer,
  children,
}: {
  // Content shown ABOVE the tabs, in its own section. It needs one: PatternFly's
  // `horizontal-subnav` Nav manages its own height and horizontal overflow and
  // expects to be the only thing in its section — putting a banner beside it
  // collapses the nav and clips the tab labels.
  header?: ReactNode;
  subnav?: ReactNode;
  fills?: boolean;
  footer?: ReactNode;
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
      {footer ? (
        <Stack hasGutter className="ct-router-stack">
          <StackItem isFilled className="ct-router-tab">
            {children}
          </StackItem>
          <StackItem>{footer}</StackItem>
        </Stack>
      ) : (
        children
      )}
    </PageSection>
  </>
);

export const Loading = () => <Spinner />;

export interface SaveStatus {
  ok: boolean;
  msg: string;
}

// A page's working copy of the JSON config, which its forms edit by leaf
// path, over the settings as the store (router-state.ts) last read them.
//
// One per page, shared by its tabs through SettingsProvider/useSettings, so
// edits survive switching tabs and "unsaved" means the whole page. The
// working copy follows the file: whenever the file changes — a save here or
// on another page, in another browser, a Discard of the saved changes — it is
// rebuilt from disk rather than kept, or a page left open would write its
// stale copy straight back over the change. Edits not saved yet survive the
// rebuild (see rebaseEdits). While a page holds unsaved edits, its sidebar
// entry says so, and leaving the web console asks first.
//
// A settings file that cannot be read (root-only, in a session with Limited
// access) is an `error`, never an empty form: `ready` stays false, so pages
// show the message instead of a form, and writeSettings refuses anyway
// without a successful read.
export function usePageSettings({ publishStatus = true }: { publishStatus?: boolean } = {}) {
  const [state, setState] = useState<LoadedSettings | null>(null);
  const [desired, setDesired] = useState<Json>({});
  const [error, setError] = useState("");
  const [baselineKnown, setBaselineKnown] = useState(false);
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState<SaveStatus | null>(null);
  // Unsaved edits, leaf path → value, in the order they were last made.
  const pending = useRef(new Map<string, Json>());
  const seen = useRef<LoadedSettings | null>(null);

  useEffect(() => {
    const sync = () => {
      const st = getRouterState();
      setError(st.error);
      setBaselineKnown(st.baselineKnown);
      if (st.settings === seen.current) {
        return;
      }
      seen.current = st.settings;
      setState(st.settings);
      if (st.settings) {
        setDesired(rebaseEdits(st.settings.desired, pending.current));
      }
    };
    sync();
    return subscribeRouterState(sync);
  }, []);

  const setLeaf = useCallback((path: string, val: Json) => {
    // Delete first so a repeated edit moves to the end: re-applying in order
    // then lets a later edit of a parent path win over an earlier child one.
    pending.current.delete(path);
    pending.current.set(path, val);
    setDesired((d) => setPath(d, path, val));
    setStatus(null);
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

  // Whether saving would change the file: an edit set back to the saved value
  // is no edit.
  const dirty = useMemo(
    () => state !== null && !deepEqual(desired, state.desired),
    [desired, state],
  );

  // Write what `build` makes of the settings as last read. When they changed
  // on disk in between, the store's watch delivers the new version; build on
  // that once more before giving up.
  const commit = useCallback(async (build: (disk: Json) => Json, after?: () => void) => {
    for (let attempt = 0; ; attempt++) {
      const base = getRouterState().settings;
      if (!base) {
        throw new Error(getRouterState().error || NOT_LOADED);
      }
      try {
        await writeSettings(build(base.desired), base);
        after?.();
        return;
      } catch (e) {
        if (!(e instanceof SettingsConflictError) || attempt > 0) {
          throw e;
        }
        await settingsChanged();
      }
    }
  }, []);

  // Save the working copy; resolves whether it was saved (errors go to
  // `status`).
  const save = useCallback(async (): Promise<boolean> => {
    setSaving(true);
    setStatus(null);
    const saved = await commit((disk) => rebaseEdits(disk, pending.current)).then(
      () => ({ ok: true, msg: "" }),
      (e: unknown) => ({ ok: false, msg: errMsg(e) }),
    );
    setStatus(saved);
    setSaving(false);
    return saved.ok;
  }, [commit]);

  // Save a change made outside the working copy (an approved exception, a
  // rule added from an event) straight to the file, carrying it into any
  // unsaved edit of the same section too (see patchWithEdits). The rest of
  // the page's unsaved edits stay unsaved. Rejects with the reason.
  const patch = useCallback(
    async (fn: (settings: Json) => Json) => {
      let next = pending.current;
      await commit(
        (disk) => {
          const patched = patchWithEdits(disk, pending.current, fn);
          next = patched.pending;
          return patched.disk;
        },
        () => {
          // The store delivered the new file (and this page rebased on it)
          // before the write resolved, still with the old edits: rebase on the
          // patched ones.
          pending.current = next;
          const base = getRouterState().settings;
          if (base) {
            setDesired(rebaseEdits(base.desired, pending.current));
          }
        },
      );
    },
    [commit],
  );

  const discard = useCallback(() => {
    pending.current.clear();
    const base = getRouterState().settings;
    if (base) {
      setDesired(base.desired);
    }
    setStatus(null);
  }, []);

  const unsaved = useMemo(
    () => (dirty ? { type: "info" as const, title: _("Unsaved changes") } : null),
    [dirty],
  );
  usePageStatus(publishStatus ? unsaved : undefined);

  useEffect(() => {
    if (!dirty) {
      return;
    }
    const warn = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);

  return {
    ready: Boolean(state),
    error,
    desired,
    effective: state?.effective ?? {},
    // Whether the running generation's settings are known (see RouterState).
    baselineKnown,
    setLeaf,
    valueOf,
    lockedOf,
    dirty,
    save,
    patch,
    discard,
    saving,
    status,
  };
}

export type Settings = ReturnType<typeof usePageSettings>;

const SettingsContext = createContext<Settings | null>(null);

// Share a page's usePageSettings with its tabs.
export const SettingsProvider = ({ value, children }: { value: Settings; children: ReactNode }) => (
  <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>
);

// The page's settings, inside a SettingsProvider.
export function useSettings(): Settings {
  const s = useContext(SettingsContext);
  if (!s) {
    throw new Error("useSettings() needs a SettingsProvider (see usePageSettings)");
  }
  return s;
}

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
