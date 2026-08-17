import { create } from "zustand";
import {
  analyzeFile,
  cancelRecovery,
  extractHash,
  getGpuInfo,
  pauseRecovery,
  resumeRecovery,
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
  RecoveryProgress,
  RecoveryStrategy,
} from "../lib/types";
import { translate } from "../lib/i18n";
import { useSettings } from "./settings";

export type Phase =
  | "select"
  | "analyzing"
  | "rejected"
  | "knowledge"
  | "configure"
  | "running"
  | "result"
  | "history";

/** The three top-level questions on the knowledge page. */
export type Knowledge = "partial" | "common" | "none";
/** Sub-choices under "I remember part of the password". */
export type SubKnowledge = "11" | "12" | "13";
export type DictionaryChoice = "default" | "custom";
/** Variation level applied to wordlist attacks (rule sets per engine). */
export type RuleLevel = "simple" | "deep" | "extreme";

/** Maps Rust error_key values to i18n message keys. */
const EXTRACTION_ERROR_I18N: Record<string, string> = {
  engine_unavailable: "analysis.extraction.engineUnavailable",
  no_hash: "analysis.extraction.noHash",
  not_encrypted: "analysis.extraction.notEncrypted",
  extraction_failed: "analysis.extraction.extractionFailed",
};

/** Maps Rust RecoverResult error_key values to i18n message keys. */
const RECOVER_ERROR_I18N: Record<string, string> = {
  hash_unreadable: "result.error.hashUnreadable",
  temp_workspace_failed: "result.error.tempWorkspaceFailed",
  hash_prepare_failed: "result.error.hashPrepareFailed",
  method_unavailable: "result.error.methodUnavailable",
  engine_unavailable: "result.error.engineUnavailable",
  missing_wordlist: "result.error.missingWordlist",
  missing_rules: "result.error.missingRules",
  cancelled: "result.error.cancelled",
};

/** Translate a RecoverResult message using its error_key. */
export function translateResultMessage(
  result: RecoverResult | null,
  lang: "en" | "zh",
): string | null {
  if (!result) return null;
  if (result.errorKey && RECOVER_ERROR_I18N[result.errorKey]) {
    return translate(lang, RECOVER_ERROR_I18N[result.errorKey] as any);
  }
  return result.message;
}

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
  /** Variation level for the history-based pattern attack (default simple). */
  ruleLevel: RuleLevel;
  /** Apply rules (best66/best64) to the dictionary attack. */
  useRules: boolean;

  maskConfig: MaskConfig;
  history: string;
  partA: string;
  partB: string;

  result: RecoverResult | null;
  gpu: GpuInfo | null;
  /** Latest live progress event from the engine while running. */
  progress: RecoveryProgress | null;
  /** Whether the user paused the running attempt. */
  paused: boolean;

  selectFile: (path: string) => void;
  analyze: () => Promise<void>;
  setKnowledge: (knowledge: Knowledge) => void;
  setSubKnowledge: (sub: SubKnowledge) => void;
  setDictionaryChoice: (choice: DictionaryChoice) => void;
  setCustomDictionaryPath: (path: string | null) => void;
  setRuleLevel: (level: RuleLevel) => void;
  setUseRules: (useRules: boolean) => void;
  setMaskConfig: (patch: Partial<MaskConfig>) => void;
  setCharGroup: (group: GroupKey, patch: Partial<CharGroup>) => void;
  setHistory: (text: string) => void;
  setPartA: (text: string) => void;
  setPartB: (text: string) => void;
  startRecovery: () => Promise<void>;
  cancel: () => void;
  setProgress: (progress: RecoveryProgress) => void;
  pause: () => void;
  resume: () => void;
  openHistory: () => void;
  closeHistory: () => void;
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
  ruleLevel: "simple" as RuleLevel,
  useRules: false,
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
  progress: null,
  paused: false,

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
      progress: null,
      paused: false,
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
      const lang = useSettings.getState().language;
      const i18nKey =
        extracted.errorKey && EXTRACTION_ERROR_I18N[extracted.errorKey]
          ? (EXTRACTION_ERROR_I18N[extracted.errorKey] as any)
          : null;
      set({
        phase: "rejected",
        analysis,
        rejectionMessage: i18nKey
          ? translate(lang, i18nKey)
          : extracted.message ?? "Could not read the password hash.",
      });
      return;
    }
    if (extracted.hashes.length > 0) {
      console.log("[HashRecover] extracted hash:", extracted.hashes);
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

  setRuleLevel: (ruleLevel) => set({ ruleLevel }),

  setUseRules: (useRules) => set({ useRules }),

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
    set({ phase: "running", result: null, progress: null, paused: false });
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
      set({ phase: "result", result, gpu, progress: null, paused: false });
      return;
    }
    set({ phase: "result", result, gpu, progress: null, paused: false });
  },

  cancel: () => {
    void cancelRecovery();
  },

  setProgress: (progress) => set({ progress }),

  pause: () => {
    void pauseRecovery();
    set({ paused: true });
  },

  resume: () => {
    void resumeRecovery();
    set({ paused: false });
  },

  openHistory: () => set({ phase: "history" }),

  closeHistory: () => set({ phase: "select" }),

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
      progress: null,
      paused: false,
    }),
}));

/** Map the wizard answers to an engine strategy. */
function buildStrategy(state: RecoveryState): RecoveryStrategy {
  const {
    knowledge,
    subKnowledge,
    dictionaryChoice,
    customDictionaryPath,
    maskConfig,
    ruleLevel,
    useRules,
  } = state;

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
          return {
            kind: "pattern",
            options: { history: state.history, ruleLevel },
          };
        case "13":
          return {
            kind: "combinator",
            options: { partA: state.partA, partB: state.partB },
          };
        default:
          break;
      }
      break;
    case "common": {
      const custom = dictionaryChoice === "custom" && customDictionaryPath;
      return {
        kind: "dictionary",
        options: {
          dictionary: custom ? customDictionaryPath : "common",
          ruleLevel: useRules ? "simple" : undefined,
        },
      };
    }
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
