import { useEffect, useState } from "react";
import { useRecovery } from "../store/recovery";
import { FileSummary } from "./FileSummary";

function formatElapsed(totalSeconds: number): string {
  const h = Math.floor(totalSeconds / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  const s = totalSeconds % 60;
  const pad = (n: number) => String(n).padStart(2, "0");
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${pad(m)}:${pad(s)}`;
}

/** Execution page. Progress is reported live by the engine; until that lands
 *  this uses a real elapsed timer and placeholders for the engine stats. */
export function RunView() {
  const gpu = useRecovery((s) => s.gpu);
  const cancel = useRecovery((s) => s.cancel);
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const startedAt = Date.now();
    const id = window.setInterval(() => {
      setElapsed(Math.floor((Date.now() - startedAt) / 1000));
    }, 1000);
    return () => window.clearInterval(id);
  }, []);

  const device = gpu?.devices[0];
  const acceleration =
    gpu?.acceleration === "gpu"
      ? "GPU acceleration enabled"
      : gpu?.acceleration === "cpu"
        ? "CPU acceleration"
        : "Detecting hardware…";

  const stats: { label: string; value: string }[] = [
    { label: "Time elapsed", value: formatElapsed(elapsed) },
    { label: "Passwords tried", value: "—" },
    { label: "Speed", value: "—" },
    { label: "Current candidate", value: "—" },
  ];

  return (
    <div className="flex flex-1 flex-col gap-5 overflow-y-auto p-6">
      <FileSummary />

      <div className="flex flex-col gap-5 rounded-lg border border-border bg-card p-6">
        <div className="flex items-center gap-3">
          <div className="h-5 w-5 animate-spin rounded-full border-2 border-border border-t-primary" />
          <h2 className="text-sm font-semibold">Recovering password…</h2>
        </div>

        <div className="h-2 w-full overflow-hidden rounded-full bg-bg">
          <div className="h-full w-1/3 animate-pulse rounded-full bg-primary" />
        </div>
        <p className="text-xs text-text-muted">
          Progress is shown in real time. Keep the window open until the attempt
          finishes.
        </p>

        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {stats.map((stat) => (
            <div key={stat.label} className="flex flex-col gap-1 rounded-md border border-border bg-bg p-3">
              <span className="text-xs text-text-muted">{stat.label}</span>
              <span className="truncate font-mono text-sm">{stat.value}</span>
            </div>
          ))}
        </div>

        {device && (
          <div className="flex flex-col gap-0.5 text-xs text-text-muted">
            <span>Detected: {device.name}</span>
            <span>{acceleration}</span>
          </div>
        )}
      </div>

      <div className="flex justify-end gap-3">
        <button
          type="button"
          disabled
          title="Pause will be available soon"
          className="rounded-md border border-border px-6 py-2.5 text-sm text-text transition-colors hover:border-primary disabled:cursor-not-allowed disabled:opacity-40"
        >
          Pause
        </button>
        <button
          type="button"
          onClick={cancel}
          className="rounded-md border border-danger/60 px-6 py-2.5 text-sm font-semibold text-danger transition-colors hover:bg-danger/10"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
