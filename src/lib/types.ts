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
}

export type StrategyKind = "dictionary" | "partial" | "pattern" | "bruteforce";

export interface StrategyOptions {
  minLength?: number;
  maxLength?: number;
  charset?: string;
  dictionary?: string;
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
