import { FileSelect } from "./components/FileSelect";
import { AnalysisView } from "./components/AnalysisView";
import { StrategySelect } from "./components/StrategySelect";
import { ResultView } from "./components/ResultView";
import { useRecovery } from "./store/recovery";
import { useAppConfig } from "./lib/appConfig";

function App() {
  const phase = useRecovery((s) => s.phase);
  const { data: config, isLoading } = useAppConfig();

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-border bg-card px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary font-bold text-bg">
            H
          </div>
          <div>
            <h1 className="text-base font-semibold leading-tight">
              {isLoading || !config ? "HashRecover" : config.productName}
            </h1>
            <p className="text-xs text-text-muted">Password recovery assistant</p>
          </div>
        </div>
      </header>

      <main className="flex min-h-0 flex-1 flex-col">
        {phase === "select" && <FileSelect />}
        {phase === "analyzing" && <AnalysisView />}
        {phase === "rejected" && <AnalysisView />}
        {phase === "strategy" && <StrategySelect />}
        {(phase === "running" || phase === "result") && <ResultView />}
      </main>
    </div>
  );
}

export default App;
