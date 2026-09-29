// This page's status in Cockpit's sidebar: an icon beside its menu entry, with
// `title` as the tooltip (cockpit/pkg/shell/nav.tsx). It is what Cockpit's own
// Software Updates page does (pkg/lib/notifications.ts `page_status.set_own`,
// which sends exactly this message; importing it would pull in a dependency
// this build does not have). The shell takes it from any frame, shown or not.
import { useEffect } from "react";

export interface PageStatus {
  type: "info" | "warning" | "error";
  title: string;
}

let published = "null";

export function publishPageStatus(status: PageStatus | null) {
  const key = JSON.stringify(status);
  if (key === published) {
    return;
  }
  published = key;
  cockpit.transport.control("notify", { page_status: status });
}

// Publish `status` for as long as it holds; `undefined` leaves the page's
// status to someone else. Cheap to call on every render: only a change is
// sent.
export function usePageStatus(status: PageStatus | null | undefined) {
  useEffect(() => {
    if (status !== undefined) {
      publishPageStatus(status);
    }
  }, [status]);
}
