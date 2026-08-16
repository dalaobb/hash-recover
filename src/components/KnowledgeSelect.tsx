import { useRecovery } from "../store/recovery";
import type { Knowledge, SubKnowledge } from "../store/recovery";
import { FileSummary } from "./FileSummary";

const KNOWLEDGE_OPTIONS: { id: Knowledge; title: string; description: string }[] = [
  {
    id: "partial",
    title: "I remember part of it",
    description: "A few characters, or the pattern the password follows.",
  },
  {
    id: "common",
    title: "It's simple and common",
    description: "The kind of password most people use.",
  },
  {
    id: "none",
    title: "I have no clue",
    description: "Try every combination — slowest but most thorough.",
  },
];

const SUB_OPTIONS: { id: SubKnowledge; title: string; description: string }[] = [
  {
    id: "11",
    title: "I know roughly the length and characters",
    description: "Pick which characters are allowed and how long it is.",
  },
  {
    id: "12",
    title: "It's based on passwords I've used before",
    description: "Try variations of your historical passwords.",
  },
  {
    id: "13",
    title: "It is made of two known parts",
    description: "Combine two sets of remembered words, numbers, or symbols.",
  },
];

export function KnowledgeSelect() {
  const knowledge = useRecovery((s) => s.knowledge);
  const subKnowledge = useRecovery((s) => s.subKnowledge);
  const setKnowledge = useRecovery((s) => s.setKnowledge);
  const setSubKnowledge = useRecovery((s) => s.setSubKnowledge);
  const toConfigure = useRecovery((s) => s.toConfigure);
  const reset = useRecovery((s) => s.reset);

  const canContinue = knowledge !== null && (knowledge !== "partial" || subKnowledge !== null);

  return (
    <div className="flex flex-1 flex-col gap-6 overflow-y-auto p-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">What do you remember about the password?</h2>
        <button
          type="button"
          onClick={reset}
          className="text-sm text-text-muted underline-offset-2 hover:text-text hover:underline"
        >
          Choose another file
        </button>
      </div>

      <FileSummary />

      <div className="flex flex-col gap-2">
        <p className="text-sm text-text-muted">
          Pick the option closest to your situation — we'll optimize the attempt automatically.
        </p>

        <div className="flex flex-col gap-2.5">
          {KNOWLEDGE_OPTIONS.map((option) => {
            const selected = knowledge === option.id;
            return (
              <div key={option.id} className="flex flex-col gap-2">
                <button
                  type="button"
                  onClick={() => setKnowledge(option.id)}
                  className={`rounded-lg border p-4 text-left transition-colors ${
                    selected
                      ? "border-primary bg-card"
                      : "border-border bg-card hover:border-primary/60"
                  }`}
                >
                  <h3 className="text-sm font-semibold">{option.title}</h3>
                  <p className="mt-1 text-xs leading-relaxed text-text-muted">
                    {option.description}
                  </p>
                </button>

                {option.id === "partial" && knowledge === "partial" && (
                  <div className="ml-6 flex flex-col gap-2 border-l border-border pl-4">
                    {SUB_OPTIONS.map((sub) => {
                      const subSelected = subKnowledge === sub.id;
                      return (
                        <button
                          key={sub.id}
                          type="button"
                          onClick={() => setSubKnowledge(sub.id)}
                          className={`rounded-lg border p-3 text-left transition-colors ${
                            subSelected
                              ? "border-primary bg-card"
                              : "border-border bg-card hover:border-primary/60"
                          }`}
                        >
                          <h4 className="text-sm font-medium">{sub.title}</h4>
                          <p className="mt-0.5 text-xs text-text-muted">{sub.description}</p>
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      <div className="mt-auto flex justify-end">
        <button
          type="button"
          disabled={!canContinue}
          onClick={toConfigure}
          className="rounded-md bg-primary px-8 py-2.5 text-sm font-semibold text-bg transition-colors hover:bg-primary-hover disabled:cursor-not-allowed disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  );
}
