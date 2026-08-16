import { useRecovery } from "../store/recovery";
import { useT } from "../lib/i18n";

const DIFFICULTY_COLORS: Record<string, string> = {
  Easy: "text-primary",
  Medium: "text-yellow-400",
  Hard: "text-danger",
};

const DIFFICULTY_LABELS: Record<string, "fileSummary.difficulty.easy" | "fileSummary.difficulty.medium" | "fileSummary.difficulty.hard"> = {
  Easy: "fileSummary.difficulty.easy",
  Medium: "fileSummary.difficulty.medium",
  Hard: "fileSummary.difficulty.hard",
};

/** File info card (logo left, details right) shown on the knowledge and
 *  running pages. */
export function FileSummary() {
  const fileName = useRecovery((s) => s.fileName);
  const filePath = useRecovery((s) => s.filePath);
  const analysis = useRecovery((s) => s.analysis);
  const extraction = useRecovery((s) => s.extraction);
  const t = useT();

  const logo = analysis?.formatId?.toUpperCase().slice(0, 2) ?? "?";
  const difficulty = extraction?.difficulty;

  return (
    <div className="flex items-center gap-4 rounded-lg border border-border bg-card p-4">
      <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-md bg-bg text-sm font-bold text-primary">
        {logo}
      </div>
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-semibold">{fileName}</p>
        <p className="truncate text-xs text-text-muted">{filePath}</p>
        <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-text-muted">
          {analysis?.formatLabel && <span>{analysis.formatLabel}</span>}
          {extraction?.encryption && (
            <span>{t("fileSummary.encryption", { value: extraction.encryption })}</span>
          )}
          {difficulty && (
            <span>
              {t("fileSummary.difficultyLabel")}
              <span className={DIFFICULTY_COLORS[difficulty] ?? "text-text-muted"}>
                {DIFFICULTY_LABELS[difficulty]
                  ? t(DIFFICULTY_LABELS[difficulty])
                  : difficulty}
              </span>
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
