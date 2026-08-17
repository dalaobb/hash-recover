import { useState } from "react";
import { useRecovery } from "../store/recovery";
import { useT } from "../lib/i18n";

export function ResultView() {
  const result = useRecovery((s) => s.result);
  const backToConfigure = useRecovery((s) => s.backToConfigure);
  const reset = useRecovery((s) => s.reset);
  const t = useT();
  const [copied, setCopied] = useState(false);

  const recovered = Boolean(result?.ok && result.password);
  const cancelled = Boolean(result?.cancelled);
  const password = result?.password ?? "";

  async function copy() {
    try {
      await navigator.clipboard.writeText(password);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-6 overflow-y-auto p-6">
      <div
        className={`flex h-12 w-12 items-center justify-center rounded-full text-xl ${
          recovered
            ? "bg-primary/15 text-primary"
            : cancelled
              ? "bg-yellow-400/15 text-yellow-400"
              : "bg-danger/15 text-danger"
        }`}
      >
        {recovered ? "✓" : cancelled ? "—" : "!"}
      </div>

      <div className="flex max-w-md flex-col items-center gap-3 text-center">
        {recovered ? (
          <>
            <h2 className="text-lg font-semibold">{t("result.recovered")}</h2>
            <p className="text-sm text-text-muted">
              {result?.reused ? t("result.fromHistory") : t("result.yourPassword")}
            </p>
            <code className="max-w-full break-all rounded-md border border-primary/40 bg-card px-4 py-2 font-mono text-base text-primary">
              {password}
            </code>
          </>
        ) : cancelled ? (
          <>
            <h2 className="text-lg font-semibold">{t("result.cancelled")}</h2>
            <p className="text-sm leading-relaxed text-text-muted">
              {t("result.cancelledBody")}
            </p>
          </>
        ) : (
          <>
            <h2 className="text-lg font-semibold">{t("result.notFound")}</h2>
            <p className="text-sm leading-relaxed text-text-muted">
              {result?.message ?? t("result.notFoundBody")}
            </p>
          </>
        )}
      </div>

      <div className="flex gap-3">
        {recovered && (
          <button
            type="button"
            onClick={() => void copy()}
            className="rounded-md bg-card px-6 py-2.5 text-sm font-semibold text-text transition-colors hover:bg-card-hover"
          >
            {copied ? t("result.copied") : t("result.copy")}
          </button>
        )}
        {!recovered && (
          <button
            type="button"
            onClick={backToConfigure}
            className="rounded-md bg-card px-6 py-2.5 text-sm font-semibold text-text transition-colors hover:bg-card-hover"
          >
            {cancelled ? t("result.tryAgain") : t("result.differentMethod")}
          </button>
        )}
        <button
          type="button"
          onClick={reset}
          className={
            recovered
              ? "rounded-md bg-primary px-6 py-2.5 text-sm font-semibold text-bg transition-colors hover:bg-primary-hover"
              : "rounded-md bg-card px-6 py-2.5 text-sm font-semibold text-text transition-colors hover:bg-card-hover"
          }
        >
          {recovered ? t("result.another") : t("result.anotherFile")}
        </button>
      </div>
    </div>
  );
}
