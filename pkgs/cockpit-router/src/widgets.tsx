// Shared presentation widgets used by more than one router view.
//
//   • RankCard     — horizontal ranking-bar list (pure CSS, no chart dep).
//   • QueriesChart — a two-series area chart (total vs blocked) over a fixed set
//                    of time buckets, rendered with @patternfly/react-charts
//                    (Victory). Both the Suricata Overview and the AdGuard
//                    Overview share these.
import { useEffect, useRef, useState } from "react";
import { Card, CardBody, CardTitle, Split, SplitItem } from "@patternfly/react-core";
import {
  Chart,
  ChartArea,
  ChartAxis,
  ChartThemeColor,
  ChartVoronoiContainer,
} from "@patternfly/react-charts/victory";

const _ = cockpit.gettext;

const BLUE = "#0066cc";
const RED = "#c9190b";

// Horizontal ranking-bar list. Pure CSS bars to avoid a charting dependency for
// the cheap "top N" case (a real chart would be overkill).
export const RankCard = ({ title, rows }: { title: string; rows: [string, number][] }) => {
  const max = Math.max(0, ...rows.map((r) => r[1])) || 1;
  return (
    <Card isCompact>
      <CardTitle>{title}</CardTitle>
      <CardBody>
        {rows.length === 0 ? (
          <div className="pf-v6-u-color-200">{_("No data in range.")}</div>
        ) : (
          rows.map(([k, count]) => (
            <div key={k} style={{ marginBlockEnd: "0.5rem" }}>
              <Split>
                <SplitItem
                  isFilled
                  style={{
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    fontSize: "0.85rem",
                  }}
                >
                  {k}
                </SplitItem>
                <SplitItem style={{ paddingInlineStart: "0.5rem", fontWeight: 600 }}>
                  {count}
                </SplitItem>
              </Split>
              <div
                style={{
                  height: "4px",
                  borderRadius: "2px",
                  background: BLUE,
                  inlineSize: `${Math.max(2, (count / max) * 100)}%`,
                }}
              />
            </div>
          ))
        )}
      </CardBody>
    </Card>
  );
};

// Measure a container's width so the (fixed-height) SVG chart can fill it and
// reflow on resize — Victory needs an explicit pixel width.
function useContainerWidth(): [React.RefObject<HTMLDivElement | null>, number] {
  const ref = useRef<HTMLDivElement | null>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const el = ref.current;
    if (!el) {
      return;
    }
    const update = () => setWidth(el.clientWidth);
    update();
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, width];
}

interface Point {
  x: number;
  y: number;
  name: string;
  t: string;
}
// The voronoi container hands the closest point to the cursor as { datum }.
interface VoronoiPoint {
  datum?: Point;
}

const CHART_HEIGHT = 230;

// Two overlaid area series (total + blocked) over `total.length` time buckets.
// The arrays are ordered oldest→newest (the last element is the current bucket).
// Bucket labels come from one of two sources:
//   • `labels` (ISO timestamps, e.g. Technitium's mainChartData.labels) — shown
//     as short local time ("HH:mm") for hour-scale buckets or "MMM d" for
//     day-scale ones. The scale comes from `labelFormat` when given (a moment-
//     style format string such as "HH:mm" or "MM/DD"), else from the spacing
//     between the first two timestamps.
//   • otherwise the legacy computed labels: bucket i sits `len-1-i` `timeUnits`
//     before now.
export const QueriesChart = ({
  title,
  total,
  blocked,
  timeUnits,
  labels,
  labelFormat,
}: {
  title: string;
  total: number[];
  blocked: number[];
  timeUnits?: "hours" | "days";
  labels?: string[];
  labelFormat?: string;
}) => {
  const [ref, width] = useContainerWidth();

  const n = total.length;

  const hoursScale = (() => {
    if (labelFormat) {
      // "HH:mm" → hour-scale; "MM/DD" / "MM/YYYY" → day-scale (case matters:
      // lowercase "mm" is minutes, uppercase "MM" is the month).
      return labelFormat.includes("H") || labelFormat.includes("mm");
    }
    if (labels && labels.length >= 2) {
      const first = Date.parse(labels[0] ?? "");
      const second = Date.parse(labels[1] ?? "");
      if (!Number.isNaN(first) && !Number.isNaN(second)) {
        // Buckets closer than ~a day apart are sub-daily → show times.
        return Math.abs(second - first) < 82_800_000;
      }
    }
    return false;
  })();

  const labelAt = (i: number): string => {
    const iso = labels?.[i];
    if (iso !== undefined) {
      const d = new Date(iso);
      if (Number.isNaN(d.getTime())) {
        return iso;
      }
      return hoursScale
        ? d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", hour12: false })
        : d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
    }
    const now = new Date();
    const back = n - 1 - i;
    if ((timeUnits ?? "days") === "hours") {
      const d = new Date(now.getTime() - back * 3_600_000);
      return `${d.getHours()}:00`;
    }
    const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() - back);
    return `${d.getMonth() + 1}/${d.getDate()}`;
  };

  const series = (values: number[], name: string): Point[] =>
    values.map((y, i) => ({ x: i, y, name, t: labelAt(i) }));
  const totalData = series(total, _("Queries"));
  const blockedData = series(blocked, _("Blocked"));

  // ~7 evenly spaced ticks so labels never crowd.
  const step = Math.max(1, Math.ceil(n / 7));
  const tickValues = totalData.map((p) => p.x).filter((x) => x % step === 0);

  const area = (data: Point[], color: string) => (
    <ChartArea
      data={data}
      interpolation="monotoneX"
      style={{ data: { fill: color, fillOpacity: 0.18, stroke: color, strokeWidth: 2 } }}
    />
  );

  return (
    <Card isCompact>
      <CardTitle>{title}</CardTitle>
      <CardBody>
        <div ref={ref} style={{ height: CHART_HEIGHT }}>
          {width > 0 && (
            <Chart
              ariaTitle={title}
              height={CHART_HEIGHT}
              width={width}
              padding={{ top: 16, bottom: 56, left: 64, right: 16 }}
              domainPadding={{ y: [0, 16] }}
              minDomain={{ y: 0 }}
              themeColor={ChartThemeColor.blue}
              legendPosition="bottom"
              legendData={[
                { name: _("Queries"), symbol: { fill: BLUE } },
                { name: _("Blocked"), symbol: { fill: RED } },
              ]}
              containerComponent={
                <ChartVoronoiContainer
                  constrainToVisibleArea
                  labels={(point: VoronoiPoint) =>
                    point.datum ? `${point.datum.t} — ${point.datum.name}: ${point.datum.y}` : ""
                  }
                />
              }
            >
              <ChartAxis
                tickValues={tickValues}
                tickFormat={(t: number) => labelAt(t)}
                fixLabelOverlap
              />
              <ChartAxis dependentAxis showGrid />
              {area(totalData, BLUE)}
              {area(blockedData, RED)}
            </Chart>
          )}
        </div>
      </CardBody>
    </Card>
  );
};
