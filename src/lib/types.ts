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
