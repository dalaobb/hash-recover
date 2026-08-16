import { open } from "@tauri-apps/plugin-dialog";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { useEffect, useState } from "react";
import { useAppConfig } from "../lib/appConfig";
import { useRecovery } from "../store/recovery";
import { useT } from "../lib/i18n";

export function FileSelect() {
  const { data: config } = useAppConfig();
  const selectFile = useRecovery((s) => s.selectFile);
  const openHistory = useRecovery((s) => s.openHistory);
  const t = useT();
  const [isDragging, setIsDragging] = useState(false);

  useEffect(() => {
    let active = true;
    let unlisten: (() => void) | undefined;
    getCurrentWebview()
      .onDragDropEvent((event) => {
        if (!active) return;
        const payload = event.payload;
        if (payload.type === "enter" || payload.type === "over") {
          setIsDragging(true);
        }
        if (payload.type === "leave") {
          setIsDragging(false);
        }
        if (payload.type === "drop") {
          setIsDragging(false);
          const path = payload.paths[0];
          if (path) selectFile(path);
        }
      })
      .then((un) => {
        if (active) unlisten = un;
      })
      .catch(() => {});
    return () => {
      active = false;
      unlisten?.();
    };
  }, [selectFile]);

  async function pick() {
    const formatFilters =
      config?.formats.map((f) => ({ name: f.label, extensions: f.extensions })) ??
      [];
    const isLinux = navigator.platform.toLowerCase().startsWith("linux");
    const filters =
      isLinux && formatFilters.length > 0
        ? [{ name: "All files", extensions: ["*"] }, ...formatFilters]
        : formatFilters;
    const file = await open({ multiple: false, filters });
    if (typeof file === "string") {
      selectFile(file);
    }
  }

  return (
    <div
      className={`relative flex flex-1 flex-col items-center justify-center gap-8 p-6 transition-colors ${
        isDragging ? "bg-primary/5" : ""
      }`}
    >
      {isDragging && (
        <div className="pointer-events-none absolute inset-4 z-10 rounded-xl border-2 border-dashed border-primary" />
      )}

      <div className="flex max-w-xl flex-col items-center gap-3 text-center">
        <h2 className="text-2xl font-semibold">{t("home.title")}</h2>
        <p className="text-sm leading-relaxed text-text-muted">{t("home.subtitle")}</p>
      </div>

      <div className="flex flex-col items-center gap-3">
        <button
          type="button"
          onClick={pick}
          className="rounded-md bg-primary px-8 py-3 text-sm font-semibold text-bg transition-colors hover:bg-primary-hover"
        >
          {t("home.selectFile")}
        </button>
        <p className="text-xs text-text-muted">{t("home.dragHint")}</p>
      </div>

      {config && config.formats.length > 0 && (
        <div className="flex flex-col items-center gap-2">
          <p className="text-xs text-text-muted">{t("home.supported")}</p>
          <div className="flex flex-wrap items-center justify-center gap-2">
            {config.formats.map((format) => (
              <span
                key={format.id}
                className="rounded-full border border-border bg-card px-3 py-1 text-xs text-text-muted"
              >
                {format.label}
              </span>
            ))}
          </div>
        </div>
      )}

      <button
        type="button"
        onClick={openHistory}
        className="rounded-md border border-border px-5 py-2 text-sm text-text transition-colors hover:border-primary"
      >
        {t("home.history")}
      </button>

      <p className="max-w-md text-center text-xs leading-relaxed text-text-muted">
        {t("home.privacy")}
      </p>
    </div>
  );
}
