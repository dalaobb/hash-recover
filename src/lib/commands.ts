import { invoke } from "@tauri-apps/api/core";
import {
  AnalyzeResult,
  ExtractResult,
  GpuInfo,
  HistoryEntry,
  RecoverRequest,
  RecoverResult,
} from "./types";

export function analyzeFile(path: string): Promise<AnalyzeResult> {
  return invoke<AnalyzeResult>("analyze_file", { path });
}

export function extractHash(path: string): Promise<ExtractResult> {
  return invoke<ExtractResult>("extract_hash", { path });
}

export function runRecovery(request: RecoverRequest): Promise<RecoverResult> {
  return invoke<RecoverResult>("recover", { request });
}

export function cancelRecovery(): Promise<void> {
  return invoke<void>("cancel_recovery");
}

export function pauseRecovery(): Promise<void> {
  return invoke<void>("pause_recovery");
}

export function resumeRecovery(): Promise<void> {
  return invoke<void>("resume_recovery");
}

export function getGpuInfo(): Promise<GpuInfo> {
  return invoke<GpuInfo>("get_gpu_info");
}

export function getHistory(): Promise<HistoryEntry[]> {
  return invoke<HistoryEntry[]>("get_history");
}

export function clearHistory(): Promise<void> {
  return invoke<void>("clear_history");
}
