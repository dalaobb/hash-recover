import { useRecovery } from "../store/recovery";
import { useT } from "../lib/i18n";

import zipSvg from "../assets/zip.svg";
import rarSvg from "../assets/rar.svg";
import sevenZipSvg from "../assets/7zip.svg";
import wordSvg from "../assets/word.svg";
import excelSvg from "../assets/excel.svg";
import powerpointSvg from "../assets/powerpoint.svg";
import pdfSvg from "../assets/pdf.svg";
import officeSvg from "../assets/office.svg";
import libreofficeSvg from "../assets/libreoffice.svg";

const FORMAT_SVGS: Record<string, string> = {
  zip: zipSvg,
  rar: rarSvg,
  "7z": sevenZipSvg,
  pdf: pdfSvg,
  word: wordSvg,
  excel: excelSvg,
  powerpoint: powerpointSvg,
  office: officeSvg,
  libreoffice: libreofficeSvg,
};

const DIFFICULTY_COLORS: Record<string, string> = {
  Easy: "text-primary",
  Medium: "text-yellow-400",
  Hard: "text-danger",
};

const DIFFICULTY_LABELS: Record<
  string,
  | "fileSummary.difficulty.easy"
  | "fileSummary.difficulty.medium"
  | "fileSummary.difficulty.hard"
> = {
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

  const formatId = analysis?.formatId ?? "";
  const logoSrc = FORMAT_SVGS[formatId];
  const difficulty = extraction?.difficulty;

  return (
    <div className="flex items-center gap-4 rounded-lg border border-border bg-card p-4">
      <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-md bg-bg">
        {logoSrc ? (
          <img src={logoSrc} alt={formatId} className="max-w-full" />
        ) : (
          <span className="text-sm font-bold text-primary">
            {formatId.toUpperCase().slice(0, 6) || "?"}
          </span>
        )}
      </div>
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-semibold">{fileName}</p>
        <p className="truncate text-xs text-text-muted mt-0.5">{filePath}</p>
        <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-text-muted">
          {analysis?.formatLabel && <span>{analysis.formatLabel}</span>}
          {extraction?.encryption && (
            <span>
              {t("fileSummary.encryption", { value: extraction.encryption })}
            </span>
          )}
          {difficulty && (
            <span>
              {t("fileSummary.difficultyLabel")}
              <span
                className={DIFFICULTY_COLORS[difficulty] ?? "text-text-muted"}
              >
                {DIFFICULTY_LABELS[difficulty]
                  ? t(DIFFICULTY_LABELS[difficulty])
                  : difficulty}
              </span>
            </span>
          )}
          {extraction?.warning && (
            <span className="text-yellow-400">{extraction.warning}</span>
          )}
        </div>
      </div>
    </div>
  );
}
