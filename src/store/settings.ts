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
  setTheme: (theme: Theme) => void;
  setFontSize: (size: FontSize) => void;
  setLanguage: (language: Language) => void;
}

export const useSettings = create<SettingsState>()(
  persist(
    (set) => ({
      theme: "dark",
      fontSize: "normal",
      language: "en",
      setTheme: (theme) => set({ theme }),
      setFontSize: (fontSize) => set({ fontSize }),
      setLanguage: (language) => set({ language }),
    }),
    { name: "hashrecover-settings" },
  ),
);
