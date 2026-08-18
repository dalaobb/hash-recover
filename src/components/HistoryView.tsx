import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { clearHistory, getHistory } from "../lib/commands";
import { useRecovery } from "../store/recovery";
import { useT } from "../lib/i18n";
import type { HistoryEntry } from "../lib/types";

function engineLabel(entry: HistoryEntry, t: ReturnType<typeof useT>): string {
  switch (entry.engine) {
    case "GPU":
      return t("history.engineGPU");
    case "CPU":
      return t("history.engineCPU");
    case "history":
      return t("history.engineHistory");
    default:
      return entry.engine;
  }
}

function strategyLabel(entry: HistoryEntry, t: ReturnType<typeof useT>): string {
  switch (entry.strategyKind) {
    case "dictionary":
      return t("history.strategy.dictionary");
    case "partial":
      return t("history.strategy.partial");
    case "pattern":
      return t("history.strategy.pattern");
    case "bruteforce":
      return t("history.strategy.bruteforce");
    case "combinator":
      return t("history.strategy.combinator");
    default:
      return entry.strategyKind;
  }
}

/** Recovery-history page: every locally recovered password, with a clear
 *  action. The same store answers repeat attempts instantly (reuse). */
export function HistoryView() {
  const closeHistory = useRecovery((s) => s.closeHistory);
  const queryClient = useQueryClient();
  const t = useT();
  const { data: entries = [], isLoading } = useQuery({
    queryKey: ["recovery-history"],
    queryFn: getHistory,
  });
  const [confirmingClear, setConfirmingClear] = useState(false);

  async function handleClear() {
    await clearHistory();
    setConfirmingClear(false);
    await queryClient.invalidateQueries({ queryKey: ["recovery-history"] });
  }

  return (
    <div className="flex flex-1 flex-col gap-5 overflow-y-auto p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-col gap-0.5">
          <h2 className="text-lg font-semibold">{t("history.title")}</h2>
          <p className="text-xs text-text-muted">{t("history.subtitle")}</p>
        </div>
        <div className="flex gap-3">
          {entries.length > 0 &&
            (confirmingClear ? (
              <button
                type="button"
                onClick={() => void handleClear()}
                className="rounded-md bg-danger px-6 py-2.5 text-sm font-semibold text-bg transition-colors hover:bg-danger/90"
              >
                {t("history.confirmClear")}
              </button>
            ) : (
              <button
                type="button"
                onClick={() => setConfirmingClear(true)}
                className="rounded-md border border-danger/60 px-6 py-2.5 text-sm font-semibold text-danger transition-colors hover:bg-danger/10"
              >
                {t("history.clear")}
              </button>
            ))}
          <button
            type="button"
            onClick={closeHistory}
            className="rounded-md border border-border px-6 py-2.5 text-sm text-text transition-colors hover:border-primary"
          >
            {t("history.back")}
          </button>
        </div>
      </div>

      {confirmingClear && (
        <p className="text-xs text-danger">{t("history.confirmClearNote")}</p>
      )}

      {isLoading ? (
        <p className="text-sm text-text-muted">{t("history.loading")}</p>
      ) : entries.length === 0 ? (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-border bg-card p-10 text-center">
          <p className="text-sm font-semibold">{t("history.emptyTitle")}</p>
          <p className="text-xs text-text-muted">{t("history.emptyBody")}</p>
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          {entries.map((entry) => (
            <div
              key={entry.hash}
              className="flex flex-col gap-2 rounded-lg border border-border bg-card p-4"
            >
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <span className="rounded-full border border-border px-2 py-0.5 text-text-muted">
                  {entry.fileName}
                </span>
                {entry.encryption && (
                  <span className="rounded-full border border-border px-2 py-0.5 text-text-muted">
                    {entry.encryption}
                  </span>
                )}
                {entry.difficulty && (
                  <span className="rounded-full border border-primary/40 px-2 py-0.5 text-primary">
                    {entry.difficulty}
                  </span>
                )}
              </div>
              <code className="max-w-full break-all rounded-md border border-primary/40 bg-bg px-3 py-1.5 font-mono text-sm text-primary">
                {entry.password}
              </code>
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-text-muted">
                <span>{engineLabel(entry, t)}</span>
                <span>•</span>
                <span>{strategyLabel(entry, t)}</span>
                <span>•</span>
                <span>{new Date(entry.recoveredAt).toLocaleString()}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
