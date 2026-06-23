// LuCI-style global changes tray, rendered above every router page. It diffs the
// Saved JSON config against the last-applied snapshot and offers Apply / Revert.
// "Save & apply" on a form (and the System page) drive it via window events:
//   • "router:changed" — the JSON was written; reload and recount.
//   • "router:apply"   — apply the saved config now.
import { useEffect, useState, useCallback, useRef } from "react";
import {
  Alert,
  AlertActionLink,
  Button,
  Spinner,
  Card,
  CardBody,
  CodeBlock,
  CodeBlockCode,
  Split,
  SplitItem,
  PageSection,
} from "@patternfly/react-core";
import { loadState, writeDesired, writeApplied, changedTopKeys, flakeHostRef, errMsg } from "./nix";
import { validateSettings } from "./schema";
import type { Json } from "./nix";

const _ = cockpit.gettext;

export const ChangesTray = () => {
  const [desired, setDesired] = useState<Json>({});
  const [applied, setApplied] = useState<Json>({});
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState("");
  const [done, setDone] = useState<{ ok: boolean } | null>(null);
  const seeded = useRef(false);
  const procRef = useRef<CockpitProcess | null>(null);
  const logRef = useRef<HTMLDivElement>(null);

  const refresh = useCallback(() => {
    void loadState().then((s) => {
      setDesired(s.desired || {});
      // First run with no snapshot yet: assume the running system matches the
      // On-disk JSON (true right after deploy) and seed the applied baseline.
      if (
        !seeded.current &&
        Object.keys(s.applied || {}).length === 0 &&
        Object.keys(s.desired || {}).length > 0
      ) {
        seeded.current = true;
        writeApplied(s.desired)
          .then(() => setApplied(s.desired))
          .catch(() => setApplied(s.desired));
      } else {
        setApplied(s.applied || {});
      }
    });
  }, []);

  useEffect(() => {
    refresh();
    const onChanged = () => refresh();
    const onApply = () => apply();
    window.addEventListener("router:changed", onChanged);
    window.addEventListener("router:apply", onApply);
    return () => {
      window.removeEventListener("router:changed", onChanged);
      window.removeEventListener("router:apply", onApply);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refresh]);

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [log]);

  const apply = useCallback(() => {
    if (procRef.current) {
      return;
    }
    setRunning(true);
    setLog("");
    setDone(null);
    // Snapshot the JSON exactly as applied once the rebuild succeeds.
    void loadState().then((s) => {
      // Validate the on-disk config against the schema before rebuilding.
      const errors = validateSettings(s.desired);
      if (errors.length > 0) {
        setLog(`Configuration does not match the schema:\n${errors.join("\n")}`);
        setDone({ ok: false });
        setRunning(false);
        return;
      }
      const proc = cockpit.spawn(
        ["nixos-rebuild", "switch", "--flake", flakeHostRef(), "--impure"],
        { superuser: "require", err: "out" },
      );
      procRef.current = proc;
      void proc.stream((d: string) => setLog((p) => p + d));
      proc
        .then(() => writeApplied(s.desired))
        .then(() => {
          setApplied(s.desired);
          setDone({ ok: true });
        })
        .catch((e: unknown) => {
          setLog((p) => `${p}\n${errMsg(e)}\n`);
          setDone({ ok: false });
        })
        .finally(() => {
          setRunning(false);
          procRef.current = null;
        });
    });
  }, []);

  const revert = useCallback(() => {
    void writeDesired(applied).then(refresh);
  }, [applied, refresh]);

  const cancel = () => {
    if (procRef.current) {
      procRef.current.close("terminated");
    }
  };

  const changed = changedTopKeys(desired, applied);

  if (!running && !done && changed.length === 0) {
    return null;
  }

  return (
    <PageSection hasBodyWrapper={false} className="ct-router-changes">
      {changed.length > 0 && !running && (
        <Alert
          variant="warning"
          isInline
          title={cockpit.format(_("Unapplied changes: $0"), changed.join(", "))}
          actionLinks={
            <>
              <AlertActionLink onClick={apply}>{_("Apply")}</AlertActionLink>
              <AlertActionLink onClick={revert}>{_("Revert")}</AlertActionLink>
            </>
          }
        />
      )}
      {(running || done) && (
        <Card isCompact>
          <CardBody>
            <Split hasGutter style={{ marginBlockEnd: "0.5rem", alignItems: "center" }}>
              <SplitItem>{running ? <Spinner size="md" /> : null}</SplitItem>
              <SplitItem isFilled>
                {running
                  ? _("Applying configuration…")
                  : done?.ok
                    ? _("Configuration applied.")
                    : _("Apply failed.")}
              </SplitItem>
              <SplitItem>
                {running ? (
                  <Button variant="link" isDanger onClick={cancel}>
                    {_("Cancel")}
                  </Button>
                ) : (
                  <Button variant="link" onClick={() => setDone(null)}>
                    {_("Dismiss")}
                  </Button>
                )}
              </SplitItem>
            </Split>
            {log && (
              <div ref={logRef} style={{ maxBlockSize: "16rem", overflow: "auto" }}>
                <CodeBlock>
                  <CodeBlockCode>{log}</CodeBlockCode>
                </CodeBlock>
              </div>
            )}
          </CardBody>
        </Card>
      )}
    </PageSection>
  );
};
