import { useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { useRecovery } from "../store/recovery";
import { FileSummary } from "./FileSummary";
import { useT } from "../lib/i18n";
import type { RecoveryProgress } from "../lib/types";

function formatElapsed(totalSeconds: number): string {
  const h = Math.floor(totalSeconds / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  const s = totalSeconds % 60;
  const pad = (n: number) => String(n).padStart(2, "0");
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${pad(m)}:${pad(s)}`;
}

function formatCount(value: number | null): string {
  return value === null ? "—" : value.toLocaleString();
}

/** Execution page. The engine streams live progress (`recovery://progress`)
 *  while it runs; this view renders the real stats and pause/cancel. */
export function RunView() {
  const gpu = useRecovery((s) => s.gpu);
  const progress = useRecovery((s) => s.progress);
  const paused = useRecovery((s) => s.paused);
  const cancel = useRecovery((s) => s.cancel);
  const pause = useRecovery((s) => s.pause);
  const resume = useRecovery((s) => s.resume);
  const setProgress = useRecovery((s) => s.setProgress);
  const t = useT();
  const [elapsed, setElapsed] = useState(0);
  const pausedAtRef = useRef<number | null>(null);
  const totalPausedMsRef = useRef(0);

  useEffect(() => {
    const startedAt = Date.now();
    const id = window.setInterval(() => {
      const pauseOffset = pausedAtRef.current
        ? Date.now() - pausedAtRef.current
        : 0;
      setElapsed(
        Math.floor(
          (Date.now() - startedAt - totalPausedMsRef.current - pauseOffset) /
            1000,
        ),
      );
    }, 1000);
    return () => window.clearInterval(id);
  }, []);

  useEffect(() => {
    if (paused) {
      pausedAtRef.current = Date.now();
    } else if (pausedAtRef.current !== null) {
      totalPausedMsRef.current += Date.now() - pausedAtRef.current;
      pausedAtRef.current = null;
    }
  }, [paused]);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    listen<RecoveryProgress>("recovery://progress", (event) => {
      setProgress(event.payload);
    }).then((fn) => {
      unlisten = fn;
    });
    return () => unlisten?.();
  }, [setProgress]);

  const device = gpu?.devices[0];
  const acceleration =
    gpu?.acceleration === "gpu"
      ? t("run.gpuEnabled")
      : gpu?.acceleration === "cpu"
        ? t("run.cpuAccel")
        : t("run.detectingHardware");

  const percent = progress?.percent ?? null;
  const total = progress?.total ?? null;
  const tried = progress?.tried ?? null;
  const cumulativeTried = progress?.cumulativeTried ?? null;
  const cumulativeTotal = progress?.cumulativeTotal ?? null;

  const stats: { label: string; value: string }[] = [
    { label: t("run.timeElapsed"), value: formatElapsed(elapsed) },
    {
      label: t("run.passwordsTried"),
      value:
        cumulativeTotal !== null && cumulativeTried !== null
          ? `${formatCount(cumulativeTried)} / ${formatCount(cumulativeTotal)}`
          : formatCount(cumulativeTried),
    },
    { label: t("run.speed"), value: progress?.speed ?? "—" },
    { label: t("run.currentCandidate"), value: progress?.candidate ?? "—" },
    { label: t("run.estimatedTime"), value: progress?.eta ?? "—" },
  ];

  return (
    <div className="flex flex-1 flex-col gap-5 overflow-y-auto p-6">
      <FileSummary />

      <div className="flex flex-col gap-5 rounded-lg border border-border bg-card p-6">
        <div className="flex items-center gap-3">
          <div className="h-5 w-5 animate-spin rounded-full border-2 border-border border-t-primary" />
          <h2 className="text-sm font-semibold">
            {paused ? t("run.paused") : t("run.recovering")}
          </h2>
          {paused && <span className="text-xs text-text-muted">{t("run.resumeHint")}</span>}
        </div>

        <div className="h-2 w-full overflow-hidden rounded-full bg-bg">
          <div
            className="h-full rounded-full bg-primary transition-[width] duration-700"
            style={{
              width: percent !== null ? `${Math.min(100, percent)}%` : "0%",
            }}
          >
            {percent === null && <div className="h-full w-1/3 animate-pulse rounded-full bg-primary" />}
          </div>
        </div>
        <div className="flex items-center justify-between text-xs text-text-muted">
          <span>
            {percent !== null
              ? t("run.complete", { percent: percent.toFixed(2) })
              : t("run.waiting")}
          </span>
          {percent !== null && tried !== null && total !== null && (
            <span>
              {t("run.ofCandidates", { tried: formatCount(tried), total: formatCount(total) })}
            </span>
          )}
        </div>

        <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
          {stats.map((stat) => (
            <div key={stat.label} className="flex flex-col gap-1 rounded-md border border-border bg-bg p-3">
              <span className="text-xs text-text-muted">{stat.label}</span>
              <span className="truncate font-mono text-sm" title={stat.value}>{stat.value}</span>
            </div>
          ))}
        </div>

        {device && (
          <div className="flex flex-col gap-0.5 text-xs text-text-muted">
            <span>{t("run.detected", { device: device.name })}</span>
            <span>{acceleration}</span>
          </div>
        )}
      </div>

      <div className="flex justify-end gap-3">
        <button
          type="button"
          onClick={paused ? resume : pause}
          className="rounded-md border border-border px-6 py-2.5 text-sm text-text transition-colors hover:border-primary"
        >
          {paused ? t("run.resume") : t("run.pause")}
        </button>
        <button
          type="button"
          onClick={cancel}
          className="rounded-md border border-danger/60 px-6 py-2.5 text-sm font-semibold text-danger transition-colors hover:bg-danger/10"
        >
          {t("run.cancel")}
        </button>
      </div>
    </div>
  );
}
