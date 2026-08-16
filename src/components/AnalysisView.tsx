import { useRecovery } from "../store/recovery";
import { useT } from "../lib/i18n";

export function AnalysisView() {
  const fileName = useRecovery((s) => s.fileName);
  const rejectionMessage = useRecovery((s) => s.rejectionMessage);
  const reset = useRecovery((s) => s.reset);
  const t = useT();

  if (rejectionMessage) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-6 p-6">
        <div className="flex max-w-md flex-col items-center gap-3 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-full bg-danger/15 text-xl">
            !
          </div>
          <h2 className="text-lg font-semibold">{t("analysis.couldNotAnalyze")}</h2>
          <p className="text-sm leading-relaxed text-text-muted">
            {rejectionMessage}
          </p>
        </div>
        <button
          type="button"
          onClick={reset}
          className="rounded-md bg-card px-6 py-2.5 text-sm font-semibold text-text transition-colors hover:bg-card-hover"
        >
          {t("analysis.chooseAnother")}
        </button>
      </div>
    );
  }

  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-4 p-6">
      <div className="h-10 w-10 animate-spin rounded-full border-2 border-border border-t-primary" />
      <h2 className="text-lg font-semibold">{t("analysis.analyzing", { file: fileName ?? "" })}</h2>
      <p className="text-sm text-text-muted">{t("analysis.detecting")}</p>
    </div>
  );
}
