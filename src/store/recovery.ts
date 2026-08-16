import { create } from "zustand";
import {
  analyzeFile,
  cancelRecovery,
  extractHash,
  getGpuInfo,
  runRecovery,
} from "../lib/commands";
import {
  buildCharset,
  defaultMaskConfig,
  maskLengths,
  MaskConfig,
  GroupKey,
  CharGroup,
} from "../lib/charsets";
import type {
  AnalyzeResult,
  ExtractResult,
  GpuInfo,
  RecoverResult,
  RecoveryStrategy,
} from "../lib/types";

export type Phase =
  | "select"
  | "analyzing"
  | "rejected"
  | "knowledge"
  | "configure"
  | "running"
  | "result";

/** The three top-level questions on the knowledge page. */
export type Knowledge = "partial" | "common" | "none";
/** Sub-choices under "I remember part of the password". */
export type SubKnowledge = "11" | "12" | "13";
export type DictionaryChoice = "default" | "custom";

interface RecoveryState {
  phase: Phase;
  filePath: string | null;
  fileName: string | null;
  analysis: AnalyzeResult | null;
  extraction: ExtractResult | null;
  hash: string | null;
  rejectionMessage: string | null;

  knowledge: Knowledge | null;
  subKnowledge: SubKnowledge | null;
  dictionaryChoice: DictionaryChoice | null;
  customDictionaryPath: string | null;

  maskConfig: MaskConfig;
  history: string;
  partA: string;
  partB: string;

  result: RecoverResult | null;
  gpu: GpuInfo | null;

  selectFile: (path: string) => void;
  analyze: () => Promise<void>;
  setKnowledge: (knowledge: Knowledge) => void;
  setSubKnowledge: (sub: SubKnowledge) => void;
  setDictionaryChoice: (choice: DictionaryChoice) => void;
  setCustomDictionaryPath: (path: string | null) => void;
  setMaskConfig: (patch: Partial<MaskConfig>) => void;
  setCharGroup: (group: GroupKey, patch: Partial<CharGroup>) => void;
  setHistory: (text: string) => void;
  setPartA: (text: string) => void;
  setPartB: (text: string) => void;
  startRecovery: () => Promise<void>;
  cancel: () => void;
  toConfigure: () => void;
  backToKnowledge: () => void;
  backToConfigure: () => void;
  reset: () => void;
}

const initialWizard = () => ({
  knowledge: null as Knowledge | null,
  subKnowledge: null as SubKnowledge | null,
  dictionaryChoice: null as DictionaryChoice | null,
  customDictionaryPath: null as string | null,
  maskConfig: defaultMaskConfig(),
  history: "",
  partA: "",
  partB: "",
});

export const useRecovery = create<RecoveryState>((set, get) => ({
  phase: "select",
  filePath: null,
  fileName: null,
  analysis: null,
  extraction: null,
  hash: null,
  rejectionMessage: null,

  ...initialWizard(),

  result: null,
  gpu: null,

  selectFile: (path) => {
    set({
      phase: "analyzing",
      filePath: path,
      fileName: path.split(/[\\/]/).pop() ?? path,
      analysis: null,
      extraction: null,
      hash: null,
      rejectionMessage: null,
      ...initialWizard(),
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
      phase: "knowledge",
      analysis,
      extraction: extracted,
      hash: extracted.hashes[0] ?? null,
    });
  },

  setKnowledge: (knowledge) => {
    set((s) => ({
      knowledge,
      subKnowledge: knowledge === "partial" ? s.subKnowledge : null,
      dictionaryChoice: knowledge === "common" ? s.dictionaryChoice : null,
    }));
  },

  setSubKnowledge: (sub) => set({ subKnowledge: sub }),

  setDictionaryChoice: (choice) => set({ dictionaryChoice: choice }),

  setCustomDictionaryPath: (path) => set({ customDictionaryPath: path }),

  setMaskConfig: (patch) => set((s) => ({ maskConfig: { ...s.maskConfig, ...patch } })),

  setCharGroup: (group, patch) =>
    set((s) => ({
      maskConfig: { ...s.maskConfig, [group]: { ...s.maskConfig[group], ...patch } },
    })),

  setHistory: (history) => set({ history }),
  setPartA: (partA) => set({ partA }),
  setPartB: (partB) => set({ partB }),

  startRecovery: async () => {
    const { filePath, hash } = get();
    if (!filePath || !hash) return;
    set({ phase: "running", result: null });
    const [result, gpu] = await Promise.all([
      runRecovery({
        filePath,
        hash,
        strategy: buildStrategy(get()),
      }),
      getGpuInfo().catch(() => null),
    ]);
    if (result.commandLines.length > 0) {
      console.log("[HashRecover] engine command lines:", result.commandLines);
    }
    if (result.cancelled) {
      set({ phase: "configure", result: null, gpu: null });
      return;
    }
    set({ phase: "result", result, gpu });
  },

  cancel: () => {
    void cancelRecovery();
  },

  toConfigure: () => set({ phase: "configure" }),

  backToKnowledge: () => set({ phase: "knowledge" }),

  backToConfigure: () => set({ phase: "configure", result: null }),

  reset: () =>
    set({
      phase: "select",
      filePath: null,
      fileName: null,
      analysis: null,
      extraction: null,
      hash: null,
      rejectionMessage: null,
      ...initialWizard(),
      result: null,
      gpu: null,
    }),
}));

/** Map the wizard answers to an engine strategy. */
function buildStrategy(state: RecoveryState): RecoveryStrategy {
  const { knowledge, subKnowledge, dictionaryChoice, customDictionaryPath, maskConfig } = state;

  switch (knowledge) {
    case "partial":
      switch (subKnowledge) {
        case "11": {
          const { min, max } = maskLengths(maskConfig);
          return {
            kind: "bruteforce",
            options: {
              minLength: min,
              maxLength: max,
              charset: buildCharset(maskConfig),
              prefix: maskConfig.prefix || undefined,
              suffix: maskConfig.suffix || undefined,
            },
          };
        }
        case "12":
          return { kind: "pattern", options: { history: state.history } };
        case "13":
          return {
            kind: "combinator",
            options: { partA: state.partA, partB: state.partB },
          };
        default:
          break;
      }
      break;
    case "common":
      return dictionaryChoice === "custom" && customDictionaryPath
        ? { kind: "dictionary", options: { dictionary: customDictionaryPath } }
        : { kind: "dictionary", options: { dictionary: "common" } };
    case "none":
      return {
        kind: "bruteforce",
        options: { minLength: 1, maxLength: 16, charset: "all" },
      };
    default:
      break;
  }

  // Fall back to the bundled common-passwords attack.
  return { kind: "dictionary", options: { dictionary: "common" } };
}
