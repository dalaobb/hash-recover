import { useRecovery } from "../store/recovery";
import type { Knowledge, SubKnowledge } from "../store/recovery";
import { FileSummary } from "./FileSummary";
import { useT } from "../lib/i18n";

const KNOWLEDGE_OPTIONS: {
  id: Knowledge;
  title:
    | "knowledge.option.partial.title"
    | "knowledge.option.common.title"
    | "knowledge.option.none.title";
  description:
    | "knowledge.option.partial.description"
    | "knowledge.option.common.description"
    | "knowledge.option.none.description";
}[] = [
  {
    id: "partial",
    title: "knowledge.option.partial.title",
    description: "knowledge.option.partial.description",
  },
  {
    id: "common",
    title: "knowledge.option.common.title",
    description: "knowledge.option.common.description",
  },
  {
    id: "none",
    title: "knowledge.option.none.title",
    description: "knowledge.option.none.description",
  },
];

const SUB_OPTIONS: {
  id: SubKnowledge;
  title:
    | "knowledge.sub.11.title"
    | "knowledge.sub.12.title"
    | "knowledge.sub.13.title";
  description:
    | "knowledge.sub.11.description"
    | "knowledge.sub.12.description"
    | "knowledge.sub.13.description";
}[] = [
  {
    id: "11",
    title: "knowledge.sub.11.title",
    description: "knowledge.sub.11.description",
  },
  {
    id: "12",
    title: "knowledge.sub.12.title",
    description: "knowledge.sub.12.description",
  },
  {
    id: "13",
    title: "knowledge.sub.13.title",
    description: "knowledge.sub.13.description",
  },
];

export function KnowledgeSelect() {
  const knowledge = useRecovery((s) => s.knowledge);
  const subKnowledge = useRecovery((s) => s.subKnowledge);
  const setKnowledge = useRecovery((s) => s.setKnowledge);
  const setSubKnowledge = useRecovery((s) => s.setSubKnowledge);
  const toConfigure = useRecovery((s) => s.toConfigure);
  const reset = useRecovery((s) => s.reset);
  const t = useT();

  const canContinue =
    knowledge !== null && (knowledge !== "partial" || subKnowledge !== null);

  return (
    <div className="flex flex-1 flex-col gap-6 overflow-y-auto p-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">{t("knowledge.title")}</h2>
        <button
          type="button"
          onClick={reset}
          className="text-sm text-text-muted underline-offset-2 hover:text-text hover:underline"
        >
          {t("knowledge.chooseAnother")}
        </button>
      </div>

      <FileSummary />

      <div className="flex flex-col gap-2">
        <p className="text-sm text-text-muted">{t("knowledge.subtitle")}</p>

        <div className="flex flex-col gap-2">
          {KNOWLEDGE_OPTIONS.map((option) => {
            const selected = knowledge === option.id;
            return (
              <div key={option.id} className="flex flex-col gap-1.5">
                <button
                  type="button"
                  onClick={() => setKnowledge(option.id)}
                  className={`flex items-center gap-3 rounded-lg border p-3 text-left transition-colors ${
                    selected
                      ? "border-primary bg-card"
                      : "border-border bg-card hover:border-primary/60"
                  }`}
                >
                  <span
                    aria-hidden
                    className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border-2 transition-colors ${
                      selected ? "border-primary" : "border-text-muted/50"
                    }`}
                  >
                    {selected && (
                      <span className="h-2 w-2 rounded-full bg-primary" />
                    )}
                  </span>
                  <span className="flex flex-col gap-0.5">
                    <h3 className="text-sm font-semibold">{t(option.title)}</h3>
                    <p className="text-xs leading-snug text-text-muted">
                      {t(option.description)}
                    </p>
                  </span>
                </button>

                {option.id === "partial" && knowledge === "partial" && (
                  <div className="ml-5 flex flex-col gap-1.5 border-l border-border pl-3">
                    {SUB_OPTIONS.map((sub) => {
                      const subSelected = subKnowledge === sub.id;
                      return (
                        <button
                          key={sub.id}
                          type="button"
                          onClick={() => setSubKnowledge(sub.id)}
                          className={`flex items-center gap-3 rounded-lg border p-2.5 text-left transition-colors ${
                            subSelected
                              ? "border-primary bg-card"
                              : "border-border bg-card hover:border-primary/60"
                          }`}
                        >
                          <span
                            aria-hidden
                            className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border-2 transition-colors ${
                              subSelected
                                ? "border-primary"
                                : "border-text-muted/50"
                            }`}
                          >
                            {subSelected && (
                              <span className="h-2 w-2 rounded-full bg-primary" />
                            )}
                          </span>
                          <span className="flex flex-col gap-0.5">
                            <h4 className="text-sm font-medium">
                              {t(sub.title)}
                            </h4>
                            <p className="text-xs text-text-muted">
                              {t(sub.description)}
                            </p>
                          </span>
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
          {t("knowledge.next")}
        </button>
      </div>
    </div>
  );
}
