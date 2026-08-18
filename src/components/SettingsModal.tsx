import { FONT_SIZE_PX, FontSize, Theme, useSettings } from "../store/settings";
import { Language, useT } from "../lib/i18n";

const FONT_SIZES: FontSize[] = ["small", "normal", "large", "larger"];
const LANGUAGES: { id: Language; label: string }[] = [
  { id: "en", label: "English" },
  { id: "zh", label: "简体中文" },
];

export function SettingsModal({ onClose }: { onClose: () => void }) {
  const t = useT();
  const theme = useSettings((s) => s.theme);
  const setTheme = useSettings((s) => s.setTheme);
  const fontSize = useSettings((s) => s.fontSize);
  const setFontSize = useSettings((s) => s.setFontSize);
  const language = useSettings((s) => s.language);
  const setLanguage = useSettings((s) => s.setLanguage);
  const gpuAcceleration = useSettings((s) => s.gpuAcceleration);
  const setGpuAcceleration = useSettings((s) => s.setGpuAcceleration);

  const themeButton = (value: Theme, label: string) => (
    <button
      key={value}
      type="button"
      onClick={() => setTheme(value)}
      className={`flex-1 rounded-md border px-3 py-2 text-sm transition-colors ${
        theme === value
          ? "border-primary bg-primary/10 font-semibold text-text"
          : "border-border text-text-muted hover:border-primary/60"
      }`}
    >
      {label}
    </button>
  );

  const languageButton = (id: Language, label: string) => (
    <button
      key={id}
      type="button"
      onClick={() => setLanguage(id)}
      className={`flex-1 rounded-md border px-3 py-2 text-sm transition-colors ${
        language === id
          ? "border-primary bg-primary/10 font-semibold text-text"
          : "border-border text-text-muted hover:border-primary/60"
      }`}
    >
      {label}
    </button>
  );

  const fontSizeButton = (size: FontSize) => (
    <button
      key={size}
      type="button"
      onClick={() => setFontSize(size)}
      className={`flex-1 rounded-md border px-2 py-2 text-sm transition-colors ${
        fontSize === size
          ? "border-primary bg-primary/10 font-semibold text-text"
          : "border-border text-text-muted hover:border-primary/60"
      }`}
    >
      <span style={{ fontSize: FONT_SIZE_PX[size] }}>
        {t(`settings.fontSizes.${size}`)}
      </span>
    </button>
  );

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-6"
      onClick={onClose}
    >
      <div
        className="flex w-full max-w-md flex-col gap-6 rounded-lg border border-border bg-card p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold">{t("settings.title")}</h2>
          <button
            type="button"
            onClick={onClose}
            aria-label={t("settings.close")}
            className="text-text-muted transition-colors hover:text-text"
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              className="h-5 w-5"
            >
              <path d="M18 6 6 18M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="flex flex-col gap-2">
          <span className="text-sm font-medium">{t("settings.language")}</span>
          <div className="flex gap-2">
            {LANGUAGES.map((lang) => languageButton(lang.id, lang.label))}
          </div>
        </div>

        <div className="flex flex-col gap-2">
          <span className="text-sm font-medium">
            {t("settings.appearance")}
          </span>
          <div className="flex gap-2">
            {themeButton("dark", t("settings.dark"))}
            {themeButton("light", t("settings.light"))}
          </div>
        </div>

        <div className="flex flex-col gap-2">
          <span className="text-sm font-medium">{t("settings.fontSize")}</span>
          <div className="flex gap-2">{FONT_SIZES.map(fontSizeButton)}</div>
        </div>

        <div className="flex items-center justify-between">
          <div className="flex flex-col gap-0.5">
            <span className="text-sm font-medium">
              {t("settings.gpuAcceleration")}
            </span>
            <span className="text-xs text-text-muted">
              {t("settings.gpuAccelerationHint")}
            </span>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={gpuAcceleration}
            onClick={() => setGpuAcceleration(!gpuAcceleration)}
            className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors ${
              gpuAcceleration ? "bg-primary" : "bg-border"
            }`}
          >
            <span
              className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transition-transform ${
                gpuAcceleration ? "translate-x-5" : "translate-x-0"
              }`}
            />
          </button>
        </div>
      </div>
    </div>
  );
}
