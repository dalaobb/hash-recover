import { useQuery } from "@tanstack/react-query";
import { invoke } from "@tauri-apps/api/core";

export interface FormatInfo {
  id: string;
  label: string;
  extensions: string[];
  extractor: string;
}

export interface AppConfig {
  variant: string;
  productName: string;
  formats: FormatInfo[];
  extractors: string[];
}

export function fetchAppConfig(): Promise<AppConfig> {
  return invoke<AppConfig>("get_app_config");
}

export function useAppConfig() {
  return useQuery({
    queryKey: ["app-config"],
    queryFn: fetchAppConfig,
  });
}

export function extensionsFilter(formats: FormatInfo[]): string {
  const extensions = new Set(formats.flatMap((f) => f.extensions));
  return [...extensions].map((ext) => `.${ext}`).join(",");
}
