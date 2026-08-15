import { useRecovery } from "../store/recovery";
import type { StrategyKind, StrategyOptions } from "../lib/types";

const STRATEGIES: {
  kind: StrategyKind;
  title: string;
  description: string;
}[] = [
  {
    kind: "dictionary",
    title: "Common passwords",
    description: "Try popular and previously leaked passwords.",
  },
  {
    kind: "partial",
    title: "Remember part of password",
    description: "You know some characters of the password.",
  },
  {
    kind: "pattern",
    title: "Password habits",
    description: "Typical patterns people use when choosing passwords.",
  },
  {
    kind: "bruteforce",
    title: "Unknown password",
    description: "Try every combination within a length range.",
  },
];

const CHARSETS: { id: string; label: string; value: string }[] = [
  { id: "alpha", label: "Letters", value: "abcdefghijklmnopqrstuvwxyz" },
  {
    id: "alphanumeric",
    label: "Letters & numbers",
    value: "abcdefghijklmnopqrstuvwxyz0123456789",
  },
  {
    id: "full",
    label: "All characters",
    value:
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{};:,.<>?",
  },
];

function OptionPanel({ kind }: { kind: StrategyKind }) {
  const options = useRecovery((s) => s.strategyOptions);
  const setOptions = useRecovery((s) => s.setStrategyOptions);

  const set = (patch: Partial<StrategyOptions>) => setOptions({ ...options, ...patch });

  if (kind === "dictionary") {
    return (
      <p className="text-sm text-text-muted">
        Uses the bundled wordlist of the most common passwords.
      </p>
    );
  }

  if (kind === "partial") {
    return (
      <label className="flex flex-col gap-1.5">
        <span className="text-sm text-text-muted">Known part of the password</span>
        <input
          type="text"
          value={options.charset ?? ""}
          onChange={(e) => set({ charset: e.target.value })}
          placeholder="e.g. summer2020"
          className="rounded-md border border-border bg-bg px-3 py-2 text-sm text-text outline-none focus:border-primary"
        />
      </label>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex gap-3">
        <label className="flex flex-col gap-1.5">
          <span className="text-sm text-text-muted">Min length</span>
          <input
            type="number"
            min={1}
            max={32}
            value={options.minLength ?? ""}
            onChange={(e) => set({ minLength: Number(e.target.value) || undefined })}
            className="w-24 rounded-md border border-border bg-bg px-3 py-2 text-sm text-text outline-none focus:border-primary"
          />
        </label>
        <label className="flex flex-col gap-1.5">
          <span className="text-sm text-text-muted">Max length</span>
          <input
            type="number"
            min={1}
            max={32}
            value={options.maxLength ?? ""}
            onChange={(e) => set({ maxLength: Number(e.target.value) || undefined })}
            className="w-24 rounded-md border border-border bg-bg px-3 py-2 text-sm text-text outline-none focus:border-primary"
          />
        </label>
      </div>
      <label className="flex flex-col gap-1.5">
        <span className="text-sm text-text-muted">Character set</span>
        <select
          value={CHARSETS.find((c) => c.value === options.charset)?.id ?? "alphanumeric"}
          onChange={(e) =>
            set({ charset: CHARSETS.find((c) => c.id === e.target.value)?.value })
          }
          className="rounded-md border border-border bg-bg px-3 py-2 text-sm text-text outline-none focus:border-primary"
        >
          {CHARSETS.map((c) => (
            <option key={c.id} value={c.id}>
              {c.label}
            </option>
          ))}
        </select>
      </label>
    </div>
  );
}

export function StrategySelect() {
  const fileName = useRecovery((s) => s.fileName);
  const formatLabel = useRecovery((s) => s.analysis?.formatLabel);
  const kind = useRecovery((s) => s.strategyKind);
  const setKind = useRecovery((s) => s.setStrategyKind);
  const startRecovery = useRecovery((s) => s.startRecovery);
  const reset = useRecovery((s) => s.reset);

  return (
    <div className="flex flex-1 flex-col gap-5 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">Choose a recovery method</h2>
          <p className="text-sm text-text-muted">
            {fileName} · detected as {formatLabel ?? "supported format"}
          </p>
        </div>
        <button
          type="button"
          onClick={reset}
          className="text-sm text-text-muted underline-offset-2 hover:text-text hover:underline"
        >
          Choose another file
        </button>
      </div>

      <div className="grid grid-cols-2 gap-3">
        {STRATEGIES.map((s) => (
          <button
            key={s.kind}
            type="button"
            onClick={() => setKind(s.kind)}
            className={`rounded-lg border p-4 text-left transition-colors ${
              kind === s.kind
                ? "border-primary bg-card"
                : "border-border bg-card hover:border-primary/60"
            }`}
          >
            <h3 className="text-sm font-semibold">{s.title}</h3>
            <p className="mt-1 text-xs leading-relaxed text-text-muted">{s.description}</p>
          </button>
        ))}
      </div>

      <div className="rounded-lg border border-border bg-card p-4">
        <OptionPanel key={kind} kind={kind} />
      </div>

      <div className="flex items-center justify-end gap-3">
        <button
          type="button"
          onClick={startRecovery}
          className="rounded-md bg-primary px-8 py-2.5 text-sm font-semibold text-bg transition-colors hover:bg-primary-hover"
        >
          Start recovery
        </button>
      </div>
    </div>
  );
}
