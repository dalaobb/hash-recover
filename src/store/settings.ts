import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { Language } from "../lib/i18n";

export type Theme = "dark" | "light";
export type FontSize = "small" | "normal" | "large" | "larger";

export const FONT_SIZE_PX: Record<FontSize, number> = {
  small: 14,
  normal: 16,
  large: 18,
  larger: 20,
};

export const FONT_SIZE_LABELS: Record<FontSize, string> = {
  small: "Small",
  normal: "Normal",
  large: "Large",
  larger: "Larger",
};

interface SettingsState {
  theme: Theme;
  fontSize: FontSize;
  language: Language;
  gpuAcceleration: boolean;
  setTheme: (theme: Theme) => void;
  setFontSize: (size: FontSize) => void;
  setLanguage: (language: Language) => void;
  setGpuAcceleration: (enabled: boolean) => void;
}

export const useSettings = create<SettingsState>()(
  persist(
    (set) => ({
      theme: "dark",
      fontSize: "normal",
      language: "en",
      gpuAcceleration: true,
      setTheme: (theme) => set({ theme }),
      setFontSize: (fontSize) => set({ fontSize }),
      setLanguage: (language) => set({ language }),
      setGpuAcceleration: (gpuAcceleration) => set({ gpuAcceleration }),
    }),
    { name: "hashrecover-settings" },
  ),
);
