// The changes panel (System → Operations) and the System page's sidebar
// status: the router's state as a whole — saved changes the running system
// does not have yet, and the rebuild that is running or last ran.
//
// Nothing here is page-local: saved changes are the settings file against the
// running generation's own copy of the settings it was built from
// (router-state.ts), and rebuilds are router-rebuild.service (rebuild-job.ts),
// so every page, browser and shell sees the same. The System page is
// preloaded (manifest.json), so its sidebar entry carries that state from the
// moment the admin logs in: an error while a rebuild's failure is not
// dismissed, info while one runs, a warning while saved changes are not
// applied. A rebuild's output stays in the journal; the panel links to it.
import { useEffect, useMemo, useState } from "react";
import {
  Alert,
  AlertActionLink,
  Badge,
  Button,
  Card,
  CardBody,
  CardTitle,
  Content,
  ExpandableSection,
  Flex,
  FlexItem,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  Progress,
  Spinner,
  Stack,
  StackItem,
} from "@patternfly/react-core";
import { superuser } from "superuser";
import { canRevertTo, errMsg } from "./nix";
import { useRouterState, writeSettings } from "./router-state";
import {
  busyLabel,
  cancelRebuild,
  dismissRebuild,
  logUrl,
  opLabel,
  outcomeLabel,
  runningLabel,
  startRebuild,
  useRebuildJob,
  useRebuildProgress,
} from "./rebuild-job";
import { isRebuildOp, outcomeOf } from "./rebuild-status";
import type { JobState, RebuildRecord } from "./rebuild-status";
import { buildFraction } from "./rebuild-progress";
import type { RebuildProgress } from "./rebuild-progress";
import { formatPath, formatValue, sectionHref, summarizeChanges } from "./sections";
import type { SectionChanges } from "./sections";
import { usePageStatus } from "./page-status";
import type { PageStatus } from "./page-status";

const _ = cockpit.gettext;

// Whether this session has administrative access: rebuilding and writing the
// settings need it, and Cockpit hides what needs it otherwise.
export function useAdmin(): boolean {
  const [allowed, setAllowed] = useState(superuser.allowed);
  useEffect(() => {
    const onChange = () => setAllowed(superuser.allowed);
    superuser.addEventListener("changed", onChange);
    return () => superuser.removeEventListener("changed", onChange);
  }, []);
  return allowed === true;
}

// Saved-but-unapplied changes by section; empty when the baseline is unknown.
function useSummary(): SectionChanges[] {
  const { settings, baselineKnown } = useRouterState();
  return useMemo(
    () => (settings && baselineKnown ? summarizeChanges(settings.applied, settings.desired) : []),
    [settings, baselineKnown],
  );
}

function failureTitle(record: RebuildRecord | null, job: Extract<JobState, { kind: "failed" }>) {
  return cockpit.format(
    _("$0: $1"),
    opLabel(record?.op ?? ""),
    outcomeLabel(job.outcome).toLowerCase(),
  );
}

// The System page's sidebar status, published while the System page exists —
// which, preloaded, is always. `dirty`: the System page's own unsaved edits.
export const SystemStatus = ({ dirty = false }: { dirty?: boolean }) => {
  const job = useRebuildJob();
  const summary = useSummary();
  const labels = summary.map((c) => _(c.section.label)).join(", ");
  const status = useMemo((): PageStatus | null => {
    if (job.kind === "failed") {
      return { type: "error", title: failureTitle(job.record, job) };
    }
    if (job.kind === "running") {
      return { type: "info", title: runningLabel(job.op) };
    }
    if (job.kind === "external") {
      return { type: "info", title: busyLabel(job) };
    }
    if (labels) {
      return {
        type: "warning",
        title: cockpit.format(_("Saved changes not applied: $0"), labels),
      };
    }
    return dirty ? { type: "info", title: _("Unsaved changes") } : null;
  }, [job, labels, dirty]);
  usePageStatus(status);
  return null;
};

// "2 min 10 s"
function duration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) {
    return cockpit.format(_("$0 s"), s);
  }
  return cockpit.format(_("$0 min $1 s"), Math.floor(s / 60), s % 60);
}

const when = (epoch: number) => new Date(epoch * 1000).toLocaleString();

function phaseText(progress: RebuildProgress | null, activating: boolean): string {
  if (activating || progress?.phase === "activating") {
    return _("Activating the new configuration");
  }
  switch (progress?.phase) {
    case "updating": {
      return _("Updating flake inputs");
    }
    case "building": {
      const total = progress.toBuild + progress.toFetch;
      return total > 0
        ? cockpit.format(_("Building: $0 of $1"), progress.built + progress.fetched, total)
        : _("Evaluating the configuration");
    }
    default: {
      return _("Starting");
    }
  }
}

// The running or last rebuild.
const JobStatus = ({
  job,
  admin,
  act,
}: {
  job: JobState;
  admin: boolean;
  act: (fn: () => Promise<void>) => void;
}) => {
  const running = job.kind === "running" ? job : null;
  const progress = useRebuildProgress(running?.invocation ?? null);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!running) {
      return;
    }
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [running]);

  if (running) {
    const fraction = progress ? buildFraction(progress) : null;
    return (
      <Stack hasGutter>
        <StackItem>
          <Flex alignItems={{ default: "alignItemsCenter" }}>
            <FlexItem>
              <Spinner size="md" />
            </FlexItem>
            <FlexItem grow={{ default: "grow" }}>
              <Content component="p">
                <strong>{runningLabel(running.op)}</strong>{" "}
                {phaseText(progress, running.activating)}
                {running.since !== null && ` · ${duration(Math.floor(now / 1000) - running.since)}`}
              </Content>
            </FlexItem>
            <FlexItem>
              <Button variant="link" onClick={() => cockpit.jump(logUrl(running.since))}>
                {_("View log")}
              </Button>
            </FlexItem>
            {admin && (
              <FlexItem>
                <Button
                  variant="secondary"
                  isDanger
                  isDisabled={running.activating}
                  onClick={() => act(cancelRebuild)}
                >
                  {_("Cancel")}
                </Button>
              </FlexItem>
            )}
          </Flex>
        </StackItem>
        {fraction !== null && (
          <StackItem>
            <Progress
              value={Math.round(fraction * 100)}
              size="sm"
              measureLocation="none"
              aria-label={_("Rebuild progress")}
            />
          </StackItem>
        )}
      </Stack>
    );
  }

  if (job.kind === "external") {
    return (
      <Flex alignItems={{ default: "alignItemsCenter" }}>
        <FlexItem>
          <Spinner size="md" />
        </FlexItem>
        <FlexItem grow={{ default: "grow" }}>{busyLabel(job)}</FlexItem>
        {job.what === "upgrade" && (
          <FlexItem>
            <Button
              variant="link"
              onClick={() =>
                cockpit.jump("/system/logs#/?priority=info&service=nixos-upgrade.service")
              }
            >
              {_("View log")}
            </Button>
          </FlexItem>
        )}
      </Flex>
    );
  }

  if (job.kind === "failed") {
    const { record } = job;
    const op = record?.op ?? "";
    return (
      <Alert
        variant={job.outcome === "switched-with-errors" ? "warning" : "danger"}
        isInline
        title={failureTitle(record, job)}
        actionLinks={
          <>
            <AlertActionLink onClick={() => cockpit.jump(logUrl(record?.startedAt))}>
              {_("View log")}
            </AlertActionLink>
            {admin && isRebuildOp(op) && (
              <AlertActionLink onClick={() => act(() => startRebuild(op))}>
                {_("Try again")}
              </AlertActionLink>
            )}
            {admin && (
              <AlertActionLink onClick={() => act(dismissRebuild)}>{_("Dismiss")}</AlertActionLink>
            )}
          </>
        }
      >
        {record?.finishedAt !== undefined &&
          cockpit.format(
            _("Ended $0. The router keeps running its previous configuration."),
            when(record.finishedAt),
          )}
      </Alert>
    );
  }

  if (job.kind !== "idle") {
    return null;
  }
  const { last } = job;
  const outcome = last ? outcomeOf(last) : null;
  if (!last || !outcome || last.finishedAt === undefined) {
    return null;
  }
  return (
    <Content component="p">
      {cockpit.format(
        _("Last run: $0 — $1, $2"),
        opLabel(last.op),
        outcomeLabel(outcome).toLowerCase(),
        when(last.finishedAt),
      )}
      {last.startedAt !== undefined && ` (${duration(last.finishedAt - last.startedAt)})`}{" "}
      <Button variant="link" isInline onClick={() => cockpit.jump(logUrl(last.startedAt))}>
        {_("View log")}
      </Button>
    </Content>
  );
};

const SectionDetail = ({ changes }: { changes: SectionChanges }) => {
  const [expanded, setExpanded] = useState(false);
  const { section } = changes;
  return (
    <Flex alignItems={{ default: "alignItemsFlexStart" }}>
      <FlexItem grow={{ default: "grow" }}>
        <ExpandableSection
          isExpanded={expanded}
          onToggle={(_e, v) => setExpanded(v)}
          toggleContent={
            <>
              {_(section.label)} <Badge isRead>{changes.changes.length}</Badge>
            </>
          }
        >
          <ul className="ct-router-change-list">
            {changes.changes.map((c, i) => {
              const where = formatPath(c.path);
              const what =
                c.before === undefined
                  ? cockpit.format(_("added $0"), formatValue(c.after))
                  : c.after === undefined
                    ? cockpit.format(_("removed $0"), formatValue(c.before))
                    : `${formatValue(c.before)} → ${formatValue(c.after)}`;
              return (
                <li key={i}>
                  {where ? <code>{where}</code> : null}
                  {where ? ": " : ""}
                  {what}
                </li>
              );
            })}
          </ul>
        </ExpandableSection>
      </FlexItem>
      <FlexItem>
        <Button variant="link" isInline onClick={() => cockpit.jump(sectionHref(section))}>
          {_("Edit")}
        </Button>
      </FlexItem>
    </Flex>
  );
};

export const ChangesPanel = () => {
  const router = useRouterState();
  const job = useRebuildJob();
  const admin = useAdmin();
  const summary = useSummary();
  const [error, setError] = useState("");
  const [confirmDiscard, setConfirmDiscard] = useState(false);

  const act = (fn: () => Promise<void>) => {
    setError("");
    fn().catch((e: unknown) => setError(errMsg(e)));
  };
  const busy = busyLabel(job);
  const { settings } = router;
  const discard = () => {
    setConfirmDiscard(false);
    act(() => (settings ? writeSettings(settings.applied, settings) : Promise.resolve()));
  };

  return (
    <Card isCompact>
      <CardTitle>{_("Changes")}</CardTitle>
      <CardBody>
        <Stack hasGutter>
          <StackItem>
            <JobStatus job={job} admin={admin} act={act} />
          </StackItem>
          {error && (
            <StackItem>
              <Alert
                variant="danger"
                isInline
                title={_("Could not complete that")}
                style={{ whiteSpace: "pre-line" }}
              >
                {error}
              </Alert>
            </StackItem>
          )}
          {settings && !router.baselineKnown && (
            <StackItem>
              <Alert variant="info" isInline title={_("Saved changes cannot be listed")}>
                {_(
                  "The running configuration does not record the settings it was built from: it predates this version, or its flake does not load the settings through nixos-router.lib. Apply once to start tracking changes.",
                )}
              </Alert>
            </StackItem>
          )}
          {settings && router.baselineKnown && (
            <StackItem>
              {summary.length === 0 ? (
                <Content component="p">{_("Everything saved is applied.")}</Content>
              ) : (
                <Stack>
                  <StackItem>
                    <Content component="p">
                      {_("Saved, but not yet applied to the running system:")}
                    </Content>
                  </StackItem>
                  {summary.map((c) => (
                    <StackItem key={c.section.key}>
                      <SectionDetail changes={c} />
                    </StackItem>
                  ))}
                </Stack>
              )}
            </StackItem>
          )}
          {admin && settings && (
            <StackItem>
              <Flex>
                <FlexItem>
                  <Button
                    variant="primary"
                    isDisabled={Boolean(busy) || (router.baselineKnown && summary.length === 0)}
                    onClick={() => act(() => startRebuild("apply"))}
                  >
                    {_("Apply changes")}
                  </Button>
                </FlexItem>
                <FlexItem>
                  <Button
                    variant="link"
                    isDanger
                    isDisabled={summary.length === 0 || !canRevertTo(settings.applied)}
                    onClick={() => setConfirmDiscard(true)}
                  >
                    {_("Discard saved changes")}
                  </Button>
                </FlexItem>
                {busy && (
                  <FlexItem alignSelf={{ default: "alignSelfCenter" }}>
                    <Content component="small">{busy}</Content>
                  </FlexItem>
                )}
              </Flex>
            </StackItem>
          )}
        </Stack>
      </CardBody>
      <Modal
        variant="small"
        isOpen={confirmDiscard}
        onClose={() => setConfirmDiscard(false)}
        aria-labelledby="discard-saved-title"
      >
        <ModalHeader
          title={_("Discard saved changes?")}
          titleIconVariant="warning"
          labelId="discard-saved-title"
        />
        <ModalBody>
          {_(
            "The settings file goes back to what the running system was built from. Every change saved since is lost; unsaved edits open on other pages are kept.",
          )}
        </ModalBody>
        <ModalFooter>
          <Button variant="danger" onClick={discard}>
            {_("Discard")}
          </Button>
          <Button variant="link" onClick={() => setConfirmDiscard(false)}>
            {_("Cancel")}
          </Button>
        </ModalFooter>
      </Modal>
    </Card>
  );
};
