import { create } from "zustand";
import { analyzeFile, extractHash, getGpuInfo, runRecovery } from "../lib/commands";
import type {
  AnalyzeResult,
  GpuInfo,
  RecoverResult,
  StrategyKind,
  StrategyOptions,
} from "../lib/types";

export type Phase = "select" | "analyzing" | "rejected" | "strategy" | "running" | "result";

interface RecoveryState {
  phase: Phase;
  filePath: string | null;
  fileName: string | null;
  analysis: AnalyzeResult | null;
  hash: string | null;
  rejectionMessage: string | null;
  strategyKind: StrategyKind;
  strategyOptions: StrategyOptions;
  result: RecoverResult | null;
  gpu: GpuInfo | null;
  selectFile: (path: string) => void;
  analyze: () => Promise<void>;
  setStrategyKind: (kind: StrategyKind) => void;
  setStrategyOptions: (options: StrategyOptions) => void;
  startRecovery: () => Promise<void>;
  backToStrategy: () => void;
  reset: () => void;
}

export const useRecovery = create<RecoveryState>((set, get) => ({
  phase: "select",
  filePath: null,
  fileName: null,
  analysis: null,
  hash: null,
  rejectionMessage: null,
  strategyKind: "dictionary",
  strategyOptions: { dictionary: "common" },
  result: null,
  gpu: null,

  selectFile: (path) => {
    set({
      phase: "analyzing",
      filePath: path,
      fileName: path.split(/[\\/]/).pop() ?? path,
      analysis: null,
      hash: null,
      rejectionMessage: null,
      result: null,
      gpu: null,
    });
    void get().analyze();
  },

  analyze: async () => {
    const { filePath } = get();
    if (!filePath) return;

    const analysis = await analyzeFile(filePath);
    if (!analysis.ok) {
      set({ phase: "rejected", analysis, rejectionMessage: analysis.message });
      return;
    }

    const extracted = await extractHash(filePath);
    if (!extracted.ok) {
      set({
        phase: "rejected",
        analysis,
        rejectionMessage: extracted.message ?? "Could not read the password hash.",
      });
      return;
    }
    set({
      phase: "strategy",
      analysis,
      hash: extracted.hashes[0] ?? null,
    });
  },

  setStrategyKind: (kind) => {
    const defaults: Record<StrategyKind, StrategyOptions> = {
      dictionary: { dictionary: "common" },
      partial: { charset: "" },
      pattern: { maxLength: 10, charset: "alpha" },
      bruteforce: { minLength: 4, maxLength: 8, charset: "alpha" },
    };
    set({ strategyKind: kind, strategyOptions: defaults[kind] });
  },

  setStrategyOptions: (options) => set({ strategyOptions: options }),

  startRecovery: async () => {
    const { filePath, hash, strategyKind, strategyOptions } = get();
    if (!filePath || !hash) return;
    set({ phase: "running", result: null });
    const [result, gpu] = await Promise.all([
      runRecovery({
        filePath,
        hash,
        strategy: { kind: strategyKind, options: strategyOptions },
      }),
      getGpuInfo().catch(() => null),
    ]);
    set({ phase: "result", result, gpu });
  },

  reset: () =>
    set({
      phase: "select",
      filePath: null,
      fileName: null,
      analysis: null,
      hash: null,
      rejectionMessage: null,
      strategyKind: "dictionary",
      strategyOptions: { dictionary: "common" },
      result: null,
      gpu: null,
    }),

  backToStrategy: () => set({ phase: "strategy", result: null }),
}));
