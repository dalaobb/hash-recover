import {
  FONT_SIZE_LABELS,
  FONT_SIZE_PX,
  FontSize,
  Theme,
  useSettings,
} from "../store/settings";

const FONT_SIZES: FontSize[] = ["small", "normal", "large", "larger"];

export function SettingsModal({ onClose }: { onClose: () => void }) {
  const theme = useSettings((s) => s.theme);
  const setTheme = useSettings((s) => s.setTheme);
  const fontSize = useSettings((s) => s.fontSize);
  const setFontSize = useSettings((s) => s.setFontSize);

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
          <h2 className="text-base font-semibold">Settings</h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close settings"
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
          <span className="text-sm font-medium">Appearance</span>
          <div className="flex gap-2">
            {themeButton("dark", "Dark")}
            {themeButton("light", "Light")}
          </div>
        </div>

        <div className="flex flex-col gap-2">
          <span className="text-sm font-medium">Font size</span>
          <div className="flex gap-2">
            {FONT_SIZES.map((size) => (
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
                  {FONT_SIZE_LABELS[size]}
                </span>
              </button>
            ))}
          </div>
          <p className="text-xs text-text-muted">Preview: this is how text will look.</p>
        </div>
      </div>
    </div>
  );
}
