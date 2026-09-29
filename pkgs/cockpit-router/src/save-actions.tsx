// The page's save control: one split button, as Cockpit's Overview page does
// Reboot / Shut down (pkg/systemd/overview.jsx). Save is the main action and
// is only enabled while the page holds unsaved edits — disabled, not hidden,
// as Cockpit does for an action that exists but is not available right now.
// The caret offers the rest: save and apply (or apply what is already
// saved), discard the edits, and review everything saved but not applied in
// the changes panel. Beside it, one line says where things stand; a rebuild's
// output is never shown here (see rebuild-job.ts).
import { useRef, useState } from "react";
import {
  Alert,
  Button,
  Divider,
  Dropdown,
  DropdownItem,
  DropdownList,
  HelperText,
  HelperTextItem,
  MenuToggle,
  MenuToggleAction,
  Spinner,
  Split,
  SplitItem,
} from "@patternfly/react-core";
import { changedTopKeys, errMsg } from "./nix";
import { getRouterState, useRouterState } from "./router-state";
import { busyLabel, outcomeLabel, runningLabel, startRebuild, useRebuildJob } from "./rebuild-job";
import { outcomeOf } from "./rebuild-status";
import type { Settings } from "./settings";

const _ = cockpit.gettext;

export const CHANGES_PANEL = "/router/system#/?tab=operations";

const LinkTo = ({ path, children }: { path: string; children: string }) => (
  <Button variant="link" isInline onClick={() => cockpit.jump(path)}>
    {children}
  </Button>
);

export const SaveActions = ({
  s,
  issues,
}: {
  s: Settings;
  // Why the page's settings must not be applied as they stand (validation);
  // saving stays possible.
  issues?: string;
}) => {
  const job = useRebuildJob();
  const { settings, baselineKnown } = useRouterState();
  const [open, setOpen] = useState(false);
  const toggleRef = useRef<HTMLButtonElement>(null);
  const [applyError, setApplyError] = useState("");
  // Once this page asked for an apply: the run that was the last one then
  // (its invocation, or null for none), so the next one to end is reported.
  // Compared by invocation, not time: the browser's clock is not the router's.
  const [before, setBefore] = useState<string | null>();

  const saved =
    settings && baselineKnown ? changedTopKeys(settings.desired, settings.applied).length : 0;
  const busy = busyLabel(job);

  const apply = async () => {
    setApplyError("");
    if (s.dirty && !(await s.save())) {
      return;
    }
    setBefore(getRouterState().rebuild?.invocation ?? null);
    await startRebuild("apply").catch((e: unknown) => {
      setApplyError(errMsg(e));
      setBefore(undefined);
    });
  };

  const applyItem = s.dirty ? (
    <DropdownItem
      key="apply"
      isDisabled={Boolean(busy || issues)}
      description={busy || issues || _("Save, then rebuild the router with every saved change")}
      onClick={() => {
        void apply();
      }}
    >
      {_("Save and apply")}
    </DropdownItem>
  ) : (
    <DropdownItem
      key="apply"
      isDisabled={Boolean(busy || issues) || (baselineKnown && saved === 0)}
      description={
        busy ||
        issues ||
        (!baselineKnown
          ? _("Rebuild the router with the saved settings")
          : saved === 0
            ? _("Everything saved is applied")
            : cockpit.format(_("Rebuild the router with $0 changed sections"), saved))
      }
      onClick={() => {
        void apply();
      }}
    >
      {_("Apply saved changes")}
    </DropdownItem>
  );

  // The one line beside the button.
  let line: React.ReactNode = null;
  if (s.saving) {
    line = <HelperTextItem icon={<Spinner size="sm" isInline />}>{_("Saving…")}</HelperTextItem>;
  } else if (job.kind === "running") {
    line = (
      <HelperTextItem icon={<Spinner size="sm" isInline />}>
        {runningLabel(job.op)} <LinkTo path={CHANGES_PANEL}>{_("View progress")}</LinkTo>
      </HelperTextItem>
    );
  } else if (job.kind === "external") {
    line = <HelperTextItem variant="indeterminate">{busy}</HelperTextItem>;
  } else if (job.kind === "failed") {
    line = (
      <HelperTextItem variant="error">
        {outcomeLabel(job.outcome)} <LinkTo path={CHANGES_PANEL}>{_("View details")}</LinkTo>
      </HelperTextItem>
    );
  } else if (before !== undefined && job.last && job.last.invocation !== before) {
    const outcome = outcomeOf(job.last);
    line = (
      <HelperTextItem variant={outcome === "succeeded" ? "success" : "warning"}>
        {outcome === "succeeded" ? _("Applied") : outcome ? outcomeLabel(outcome) : ""}
      </HelperTextItem>
    );
  } else if (s.status?.ok && saved > 0) {
    line = (
      <HelperTextItem>
        {_("Saved, not applied yet.")} <LinkTo path={CHANGES_PANEL}>{_("Review")}</LinkTo>
      </HelperTextItem>
    );
  }

  return (
    <>
      {s.status && !s.status.ok && (
        <Alert
          variant="danger"
          isInline
          title={_("Could not save settings")}
          style={{ marginBlockEnd: "0.5rem", whiteSpace: "pre-line" }}
        >
          {s.status.msg}
        </Alert>
      )}
      {applyError && (
        <Alert
          variant="danger"
          isInline
          title={_("Could not apply settings")}
          style={{ marginBlockEnd: "0.5rem", whiteSpace: "pre-line" }}
        >
          {applyError}
        </Alert>
      )}
      <Split hasGutter style={{ alignItems: "center" }}>
        <SplitItem>
          <Dropdown
            isOpen={open}
            onOpenChange={setOpen}
            onSelect={() => setOpen(false)}
            popperProps={{ position: "left" }}
            toggle={{
              toggleRef,
              toggleNode: (
                <MenuToggle
                  ref={toggleRef}
                  variant="primary"
                  isExpanded={open}
                  onClick={() => setOpen(!open)}
                  aria-label={_("More save actions")}
                  splitButtonItems={[
                    <MenuToggleAction
                      key="save"
                      id="router-save"
                      isDisabled={!s.dirty || s.saving}
                      onClick={() => {
                        void s.save();
                      }}
                    >
                      {_("Save")}
                    </MenuToggleAction>,
                  ]}
                />
              ),
            }}
          >
            <DropdownList>
              {applyItem}
              <DropdownItem key="discard" isDisabled={!s.dirty || s.saving} onClick={s.discard}>
                {_("Discard unsaved changes")}
              </DropdownItem>
              <Divider component="li" key="divider" />
              <DropdownItem key="review" onClick={() => cockpit.jump(CHANGES_PANEL)}>
                {_("Review saved changes…")}
              </DropdownItem>
            </DropdownList>
          </Dropdown>
        </SplitItem>
        {line && (
          <SplitItem isFilled>
            <HelperText>{line}</HelperText>
          </SplitItem>
        )}
      </Split>
    </>
  );
};
