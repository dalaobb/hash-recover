import { useEffect, useState } from "react";
import { FileSelect } from "./components/FileSelect";
import { AnalysisView } from "./components/AnalysisView";
import { KnowledgeSelect } from "./components/KnowledgeSelect";
import { ConfigureView } from "./components/ConfigureView";
import { RunView } from "./components/RunView";
import { ResultView } from "./components/ResultView";
import { SettingsModal } from "./components/SettingsModal";
import { useRecovery } from "./store/recovery";
import { useAppConfig } from "./lib/appConfig";
import { FONT_SIZE_PX, useSettings } from "./store/settings";

const STEPS = [
  { label: "File", phases: ["select", "analyzing", "rejected"] },
  { label: "What you know", phases: ["knowledge"] },
  { label: "Configure", phases: ["configure"] },
  { label: "Recover", phases: ["running"] },
  { label: "Result", phases: ["result"] },
] as const;

function StepBar({ active }: { active: number }) {
  return (
    <div className="flex items-center justify-center gap-2 border-b border-border bg-card px-6 py-3">
      {STEPS.map((step, index) => {
        const done = index < active;
        const current = index === active;
        return (
          <div key={step.label} className="flex items-center gap-2">
            <div
              className={`flex items-center gap-2 rounded-full px-3 py-1 text-xs transition-colors ${
                current
                  ? "bg-primary font-semibold text-bg"
                  : done
                    ? "text-primary"
                    : "text-text-muted"
              }`}
            >
              <span
                className={`flex h-4 w-4 items-center justify-center rounded-full text-[10px] ${
                  current ? "bg-bg/20" : done ? "bg-primary/15" : "bg-border"
                }`}
              >
                {done ? "✓" : index + 1}
              </span>
              {step.label}
            </div>
            {index < STEPS.length - 1 && <span className="text-border">›</span>}
          </div>
        );
      })}
    </div>
  );
}

function App() {
  const phase = useRecovery((s) => s.phase);
  const { data: config, isLoading } = useAppConfig();
  const theme = useSettings((s) => s.theme);
  const fontSize = useSettings((s) => s.fontSize);
  const [settingsOpen, setSettingsOpen] = useState(false);

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = theme;
    root.style.fontSize = `${FONT_SIZE_PX[fontSize]}px`;
  }, [theme, fontSize]);

  const stepIndex = STEPS.findIndex((step) => (step.phases as readonly string[]).includes(phase));

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
        <button
          type="button"
          onClick={() => setSettingsOpen(true)}
          aria-label="Open settings"
          title="Settings"
          className="rounded-md p-2 text-text-muted transition-colors hover:bg-card-hover hover:text-text"
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
            className="h-5 w-5"
          >
            <circle cx="12" cy="12" r="3" />
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
          </svg>
        </button>
      </header>

      {stepIndex >= 0 && <StepBar active={stepIndex} />}

      <main className="flex min-h-0 flex-1 flex-col">
        {phase === "select" && <FileSelect />}
        {(phase === "analyzing" || phase === "rejected") && <AnalysisView />}
        {phase === "knowledge" && <KnowledgeSelect />}
        {phase === "configure" && <ConfigureView />}
        {phase === "running" && <RunView />}
        {phase === "result" && <ResultView />}
      </main>

      {settingsOpen && <SettingsModal onClose={() => setSettingsOpen(false)} />}
    </div>
  );
}

export default App;
