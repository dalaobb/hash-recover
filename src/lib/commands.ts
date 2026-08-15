import { invoke } from "@tauri-apps/api/core";
import {
  AnalyzeResult,
  ExtractResult,
  GpuInfo,
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

export function getGpuInfo(): Promise<GpuInfo> {
  return invoke<GpuInfo>("get_gpu_info");
}
