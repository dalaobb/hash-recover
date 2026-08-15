import { useRecovery } from "../store/recovery";

export function ResultView() {
  const phase = useRecovery((s) => s.phase);
  const result = useRecovery((s) => s.result);
  const gpu = useRecovery((s) => s.gpu);
  const strategyKind = useRecovery((s) => s.strategyKind);
  const reset = useRecovery((s) => s.reset);
  const backToStrategy = useRecovery((s) => s.backToStrategy);

  if (phase === "running") {
    const device = gpu?.devices[0];
    const acceleration =
      gpu?.acceleration === "gpu"
        ? "GPU acceleration enabled"
        : gpu?.acceleration === "cpu"
          ? "CPU acceleration"
          : "Detecting hardware…";
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-4 p-6">
        <div className="h-10 w-10 animate-spin rounded-full border-2 border-border border-t-primary" />
        <h2 className="text-lg font-semibold">Running recovery</h2>
        <p className="text-sm text-text-muted">Trying candidate passwords…</p>
        {device && (
          <div className="flex flex-col items-center gap-0.5 text-xs text-text-muted">
            <span>Detected: {device.name}</span>
            <span>{acceleration}</span>
          </div>
        )}
      </div>
    );
  }

  const recovered = Boolean(result?.ok && result.password);
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-6 p-6">
      <div
        className={`flex h-12 w-12 items-center justify-center rounded-full text-xl ${
          recovered ? "bg-primary/15 text-primary" : "bg-danger/15"
        }`}
      >
        {recovered ? "✓" : "!"}
      </div>

      <div className="flex max-w-md flex-col items-center gap-3 text-center">
        {recovered ? (
          <>
            <h2 className="text-lg font-semibold">Password recovered</h2>
            <p className="text-sm text-text-muted">Your password is:</p>
            <code className="rounded-md border border-primary/40 bg-card px-4 py-2 font-mono text-base text-primary">
              {result?.password}
            </code>
          </>
        ) : (
          <>
            <h2 className="text-lg font-semibold">Password not found</h2>
            <p className="text-sm leading-relaxed text-text-muted">
              {result?.message ?? "The recovery attempt did not find the password."}
            </p>
          </>
        )}
      </div>

      <div className="flex gap-3">
        {!recovered && (
          <button
            type="button"
            onClick={backToStrategy}
            className="rounded-md bg-card px-6 py-2.5 text-sm font-semibold text-text transition-colors hover:bg-card-hover"
          >
            Try a different method
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
          {recovered ? "Recover another password" : "Choose another file"}
        </button>
      </div>

      {!recovered && (
        <p className="text-xs text-text-muted">Method: {strategyKind}</p>
      )}
    </div>
  );
}
