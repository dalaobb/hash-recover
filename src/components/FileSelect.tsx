import { open } from "@tauri-apps/plugin-dialog";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { useEffect, useState } from "react";
import { useAppConfig } from "../lib/appConfig";
import { useRecovery } from "../store/recovery";

export function FileSelect() {
  const { data: config } = useAppConfig();
  const selectFile = useRecovery((s) => s.selectFile);
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
        <h2 className="text-2xl font-semibold">Recover a forgotten password</h2>
        <p className="text-sm leading-relaxed text-text-muted">
          Select an encrypted file. HashRecover detects its format, extracts the
          password hash, and runs a recovery engine for you — no technical
          setup required.
        </p>
      </div>

      <div className="flex flex-col items-center gap-3">
        <button
          type="button"
          onClick={pick}
          className="rounded-md bg-primary px-8 py-3 text-sm font-semibold text-bg transition-colors hover:bg-primary-hover"
        >
          Select file
        </button>
        <p className="text-xs text-text-muted">or drag &amp; drop a file anywhere</p>
      </div>

      {config && config.formats.length > 0 && (
        <div className="flex flex-col items-center gap-2">
          <p className="text-xs text-text-muted">Supported in this edition</p>
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

      <p className="max-w-md text-center text-xs leading-relaxed text-text-muted">
        Your files never leave this device. Hashes are processed locally and no
        data is uploaded.
      </p>
    </div>
  );
}
