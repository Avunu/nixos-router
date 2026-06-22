// Reusable building blocks for the Settings tabs and config pages: a banner that
// reminds the user to apply pending changes, a simple string-list editor, and
// small load/save helpers that wrap the nix.ts read/write functions.
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
} from "@patternfly/react-core";
import { markPending, isPending } from "./nix";

const _ = cockpit.gettext;

// Shown at the top of every settings surface once any value has been written but
// not yet applied. Cleared by the System page after a successful rebuild.
export const PendingBanner = () =>
  isPending() ? (
    <Alert
      variant="warning"
      isInline
      title={_("Configuration changed — open the System page and apply it for changes to take effect.")}
    />
  ) : null;

// Load async data into state once, exposing loading/error. Returns a setter so
// forms can edit a local working copy seeded from the effective config.
export function useLoader<T>(
  loader: () => Promise<T>,
  initial: T,
): {
  value: T;
  setValue: React.Dispatch<React.SetStateAction<T>>;
  loading: boolean;
  error: string;
} {
  const [value, setValue] = useState<T>(initial);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    loader()
      .then((v) => {
        if (live) {
          setValue(v);
          setLoading(false);
        }
      })
      .catch((e: any) => {
        if (live) {
          setError(e.message || String(e));
          setLoading(false);
        }
      });
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return { value, setValue, loading, error };
}

// Save-button state machine shared by every form: runs the writer(s), marks the
// config pending on success, and surfaces a status Alert.
export function useSaver() {
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState<{ ok: boolean; msg: string } | null>(null);
  const run = useCallback((fn: () => Promise<unknown>) => {
    setSaving(true);
    setStatus(null);
    Promise.resolve()
      .then(fn)
      .then(() => {
        markPending();
        setStatus({ ok: true, msg: _("Saved. Apply changes on the System page.") });
      })
      .catch((e: any) => setStatus({ ok: false, msg: e.message || String(e) }))
      .finally(() => setSaving(false));
  }, []);
  return { saving, status, run };
}

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

export const Loading = () => <Spinner />;

// Edit a list of strings (allow/block lists, DNS upstreams, UT Capitole
// categories, …) as removable chips plus an add field.
export const ListEditor = ({
  value,
  onChange,
  placeholder,
}: {
  value: string[];
  onChange: (v: string[]) => void;
  placeholder?: string;
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
              <Label key={item} onClose={() => onChange(value.filter((x) => x !== item))}>
                {item}
              </Label>
            ))}
          </LabelGroup>
        )}
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
      </SplitItem>
    </Split>
  );
};
