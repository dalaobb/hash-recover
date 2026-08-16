import { AppConfig } from "./appConfig";

export interface AnalyzeResult {
  ok: boolean;
  formatId: string | null;
  formatLabel: string | null;
  message: string | null;
}

export interface ExtractResult {
  ok: boolean;
  hashes: string[];
  message: string | null;
  /** Friendly encryption name (e.g. "AES-256"), shown on the file card. */
  encryption: string | null;
  /** "Easy", "Medium" or "Hard", shown on the file card. */
  difficulty: string | null;
}

export type StrategyKind = "dictionary" | "partial" | "pattern" | "bruteforce" | "combinator";

export interface StrategyOptions {
  minLength?: number;
  maxLength?: number;
  charset?: string;
  dictionary?: string;
  /** Literal prefix baked into the mask (remembered part of the password). */
  prefix?: string;
  /** Literal suffix baked into the mask. */
  suffix?: string;
  /** Multiline historical passwords used as the pattern attack wordlist. */
  history?: string;
  /** First part list for the combinator attack. */
  partA?: string;
  /** Second part list for the combinator attack. */
  partB?: string;
  /** Friendly variation level driving which rule set is applied to a
   *  wordlist attack: "simple", "deep" or "extreme". */
  ruleLevel?: string;
}

export interface RecoveryStrategy {
  kind: StrategyKind;
  options: StrategyOptions;
}

export interface RecoverRequest {
  filePath: string;
  hash: string;
  strategy: RecoveryStrategy;
}

export interface RecoverResult {
  ok: boolean;
  password: string | null;
  message: string | null;
  /** True when the user cancelled the attempt. */
  cancelled: boolean;
  /** True when the password came from local recovery history (reuse). */
  reused: boolean;
  /** The engine command lines that were invoked, for debug logging. */
  commandLines: string[];
}

/** One locally recovered password, stored for reuse and the history view. */
export interface HistoryEntry {
  /** Bare normalized hash (`$pdf$...`), the reuse key. */
  hash: string;
  /** Base file name the hash was recovered from. */
  fileName: string;
  /** Friendly encryption name (e.g. "AES-256"). */
  encryption: string | null;
  /** "Easy", "Medium" or "Hard". */
  difficulty: string | null;
  /** The recovered password. */
  password: string;
  /** Which engine found it: "hashcat", "john" or "history" (reuse). */
  engine: string;
  /** Strategy kind that recovered it ("dictionary", "pattern", ...). */
  strategyKind: string;
  /** Unix timestamp in milliseconds. */
  recoveredAt: number;
}

/** Live progress pushed from the engine via `recovery://progress`. Every field
 *  is optional: Hashcat reports all of them, John only percent/speed. */
export interface RecoveryProgress {
  /** Candidates tested so far. */
  tried: number | null;
  /** Total candidates in the attack. */
  total: number | null;
  /** Completion as 0..100. */
  percent: number | null;
  /** Candidate rate, e.g. "1.2 MH/s". */
  speed: string | null;
  /** The candidate currently being tested. */
  candidate: string | null;
  /** Estimated time remaining as printed by the engine. */
  eta: string | null;
}

export type DeviceKind = "gpu" | "cpu" | "other";

export interface DeviceInfo {
  name: string;
  kind: DeviceKind;
}

export interface GpuInfo {
  devices: DeviceInfo[];
  acceleration: "gpu" | "cpu" | "none";
}

export type { AppConfig };
