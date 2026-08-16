import { useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { useRecovery } from "../store/recovery";
import {
  buildCharset,
  GROUP_CHARS,
  GroupKey,
  maskLengths,
} from "../lib/charsets";
import { CharGroupPicker } from "./CharGroupPicker";

const TABS = [
  { id: "length", label: "Length" },
  { id: "edges", label: "Start & end" },
  { id: "lower", label: "Lowercase" },
  { id: "upper", label: "Uppercase" },
  { id: "digit", label: "Digits" },
  { id: "special", label: "Symbols" },
  { id: "overview", label: "Overview" },
] as const;

type TabId = (typeof TABS)[number]["id"];

const GROUP_LABELS: Record<GroupKey, string> = {
  lower: "Lowercase",
  upper: "Uppercase",
  digit: "Digits",
  special: "Symbols",
};

const inputCls =
  "rounded-md border border-border bg-bg px-3 py-2 text-sm text-text outline-none focus:border-primary";

function LengthTab() {
  const maskConfig = useRecovery((s) => s.maskConfig);
  const setMaskConfig = useRecovery((s) => s.setMaskConfig);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-2">
        <label className="flex items-center gap-2 text-sm">
          <input
            type="radio"
            className="accent-primary"
            checked={maskConfig.lengthMode === "fixed"}
            onChange={() => setMaskConfig({ lengthMode: "fixed" })}
          />
          Exact length
        </label>
        {maskConfig.lengthMode === "fixed" && (
          <div className="flex items-center gap-2 pl-6">
            <span className="text-sm text-text-muted">Length</span>
            <input
              type="number"
              min={1}
              max={32}
              value={maskConfig.fixedLength}
              onChange={(e) =>
                setMaskConfig({ fixedLength: Math.max(1, Number(e.target.value) || 1) })
              }
              className={`${inputCls} w-24`}
            />
          </div>
        )}
      </div>

      <label className="flex items-center gap-2 text-sm">
        <input
          type="radio"
          className="accent-primary"
          checked={maskConfig.lengthMode === "range"}
          onChange={() => setMaskConfig({ lengthMode: "range" })}
        />
        Between two lengths
      </label>
      {maskConfig.lengthMode === "range" && (
        <div className="flex items-center gap-2 pl-6">
          <span className="text-sm text-text-muted">From</span>
          <input
            type="number"
            min={1}
            max={32}
            value={maskConfig.minLength}
            onChange={(e) =>
              setMaskConfig({ minLength: Math.max(1, Number(e.target.value) || 1) })
            }
            className={`${inputCls} w-24`}
          />
          <span className="text-sm text-text-muted">to</span>
          <input
            type="number"
            min={1}
            max={32}
            value={maskConfig.maxLength}
            onChange={(e) =>
              setMaskConfig({ maxLength: Math.max(1, Number(e.target.value) || 1) })
            }
            className={`${inputCls} w-24`}
          />
        </div>
      )}

      <label className="flex items-center gap-2 text-sm">
        <input
          type="radio"
          className="accent-primary"
          checked={maskConfig.lengthMode === "unknown"}
          onChange={() => setMaskConfig({ lengthMode: "unknown" })}
        />
        No idea (1–16 characters)
      </label>
    </div>
  );
}

function EdgesTab() {
  const maskConfig = useRecovery((s) => s.maskConfig);
  const setMaskConfig = useRecovery((s) => s.setMaskConfig);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-1.5">
        <label className="text-sm text-text-muted" htmlFor="prefix">
          The password starts with
        </label>
        <input
          id="prefix"
          value={maskConfig.prefix}
          onChange={(e) => setMaskConfig({ prefix: e.target.value })}
          placeholder="e.g. summer2024 — leave empty if unknown"
          className={`${inputCls} max-w-sm font-mono`}
        />
      </div>
      <div className="flex flex-col gap-1.5">
        <label className="text-sm text-text-muted" htmlFor="suffix">
          The password ends with
        </label>
        <input
          id="suffix"
          value={maskConfig.suffix}
          onChange={(e) => setMaskConfig({ suffix: e.target.value })}
          placeholder="e.g. ! — leave empty if unknown"
          className={`${inputCls} max-w-sm font-mono`}
        />
      </div>
      <p className="text-xs text-text-muted">
        These parts are treated as fixed. The rest is filled with the characters
        you allow on the other tabs.
      </p>
    </div>
  );
}

function GroupTab({ group, label }: { group: GroupKey; label: string }) {
  const maskConfig = useRecovery((s) => s.maskConfig);
  const setCharGroup = useRecovery((s) => s.setCharGroup);
  const chars = GROUP_CHARS[group];

  return (
    <CharGroupPicker
      label={label}
      chars={chars}
      state={maskConfig[group]}
      onChange={(patch) => setCharGroup(group, patch)}
      display={(c) => (c === " " ? "space" : c)}
    />
  );
}

function OverviewTab() {
  const maskConfig = useRecovery((s) => s.maskConfig);
  const { min, max } = maskLengths(maskConfig);
  const charset = buildCharset(maskConfig);

  const groups: { key: GroupKey; count: number }[] = (["lower", "upper", "digit", "special"] as GroupKey[]).map(
    (key) => ({ key, count: GROUP_CHARS[key].length }),
  );

  return (
    <div className="flex flex-col gap-4 text-sm">
      <div className="rounded-md border border-border bg-bg p-4">
        <table className="w-full">
          <tbody className="divide-y divide-border">
            <tr>
              <td className="py-1.5 text-text-muted">Length</td>
              <td className="py-1.5 text-right">
                {min === max ? `${min} characters` : `${min}–${max} characters`}
              </td>
            </tr>
            <tr>
              <td className="py-1.5 text-text-muted">Starts with</td>
              <td className="py-1.5 text-right font-mono">{maskConfig.prefix || "—"}</td>
            </tr>
            <tr>
              <td className="py-1.5 text-text-muted">Ends with</td>
              <td className="py-1.5 text-right font-mono">{maskConfig.suffix || "—"}</td>
            </tr>
            {groups.map(({ key, count }) => {
              const g = maskConfig[key];
              const full = g.all;
              const none = !g.all && g.selected.length === 0;
              return (
                <tr key={key}>
                  <td className="py-1.5 text-text-muted">{GROUP_LABELS[key]}</td>
                  <td className="py-1.5 text-right">
                    {full ? `all (${count})` : none ? "excluded" : `${g.selected.length} of ${count}`}
                  </td>
                </tr>
              );
            })}
            <tr>
              <td className="py-1.5 text-text-muted">Character set</td>
              <td className="py-1.5 text-right font-mono">
                {charset === "all" ? "all printable" : charset}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p className="text-xs leading-relaxed text-text-muted">
        We'll try every combination of the selected characters, starting with
        the fixed parts above. Fewer characters and a narrower length range make
        the attempt much faster.
      </p>
    </div>
  );
}

function PartialConfig() {
  const subKnowledge = useRecovery((s) => s.subKnowledge);
  const [tab, setTab] = useState<TabId>("length");
  const history = useRecovery((s) => s.history);
  const setHistory = useRecovery((s) => s.setHistory);
  const partA = useRecovery((s) => s.partA);
  const setPartA = useRecovery((s) => s.setPartA);
  const partB = useRecovery((s) => s.partB);
  const setPartB = useRecovery((s) => s.setPartB);

  if (subKnowledge === "12") {
    return (
      <div className="flex flex-col gap-2">
        <label className="text-sm text-text-muted" htmlFor="history">
          Historical passwords, one per line
        </label>
        <textarea
          id="history"
          rows={6}
          value={history}
          onChange={(e) => setHistory(e.target.value)}
          placeholder={"password123\npassword!\npassw0rd"}
          className={`${inputCls} resize-y font-mono`}
        />
        <p className="text-xs text-text-muted">
          We'll try these and common variations of them (case changes, numbers,
          symbols, years).
        </p>
      </div>
    );
  }

  if (subKnowledge === "13") {
    return (
      <div className="flex flex-col gap-4">
        <div className="flex flex-col gap-1.5">
          <label className="text-sm text-text-muted" htmlFor="partA">
            Part 1 — words or numbers you remember, one per line
          </label>
          <textarea
            id="partA"
            rows={5}
            value={partA}
            onChange={(e) => setPartA(e.target.value)}
            placeholder={"john\nmary"}
            className={`${inputCls} resize-y font-mono`}
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <label className="text-sm text-text-muted" htmlFor="partB">
            Part 2 — one per line
          </label>
          <textarea
            id="partB"
            rows={5}
            value={partB}
            onChange={(e) => setPartB(e.target.value)}
            placeholder={"1988\n2024\n!"}
            className={`${inputCls} resize-y font-mono`}
          />
        </div>
        <p className="text-xs text-text-muted">
          We'll combine every Part 1 entry with every Part 2 entry (Part 1 first).
        </p>
      </div>
    );
  }

  // subKnowledge === "11" (or unset): character/length tabs.
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap gap-1 rounded-md border border-border bg-card p-1">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={`rounded px-3 py-1.5 text-sm transition-colors ${
              tab === t.id
                ? "bg-primary font-semibold text-bg"
                : "text-text-muted hover:text-text"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>
      <div className="rounded-lg border border-border bg-card p-5">
        {tab === "length" && <LengthTab />}
        {tab === "edges" && <EdgesTab />}
        {tab === "lower" && <GroupTab group="lower" label="Lowercase letters" />}
        {tab === "upper" && <GroupTab group="upper" label="Uppercase letters" />}
        {tab === "digit" && <GroupTab group="digit" label="Digits" />}
        {tab === "special" && <GroupTab group="special" label="Symbols" />}
        {tab === "overview" && <OverviewTab />}
      </div>
    </div>
  );
}

function CommonConfig() {
  const dictionaryChoice = useRecovery((s) => s.dictionaryChoice);
  const setDictionaryChoice = useRecovery((s) => s.setDictionaryChoice);
  const customDictionaryPath = useRecovery((s) => s.customDictionaryPath);
  const setCustomDictionaryPath = useRecovery((s) => s.setCustomDictionaryPath);

  async function pickDictionary() {
    const file = await open({
      multiple: false,
      title: "Choose a word list",
      filters: [{ name: "Word lists", extensions: ["txt"] }],
    });
    if (typeof file === "string") {
      setCustomDictionaryPath(file);
    }
  }

  return (
    <div className="flex flex-col gap-2.5">
      <label className="flex items-start gap-2.5 rounded-lg border border-border bg-card p-4 text-sm">
        <input
          type="radio"
          className="mt-0.5 accent-primary"
          checked={dictionaryChoice !== "custom"}
          onChange={() => setDictionaryChoice("default")}
        />
        <span>
          <span className="font-semibold">Use the built-in common passwords</span>
          <span className="block text-xs text-text-muted">
            A curated list of the most popular passwords, with common variations.
          </span>
        </span>
      </label>

      <label className="flex items-start gap-2.5 rounded-lg border border-border bg-card p-4 text-sm">
        <input
          type="radio"
          className="mt-0.5 accent-primary"
          checked={dictionaryChoice === "custom"}
          onChange={() => setDictionaryChoice("custom")}
        />
        <span>
          <span className="font-semibold">Use my own word list</span>
          <span className="block text-xs text-text-muted">
            A .txt file with one candidate per line.
          </span>
        </span>
      </label>

      {dictionaryChoice === "custom" && (
        <div className="flex items-center gap-3 pl-7">
          <span className="max-w-xs truncate font-mono text-xs text-text-muted">
            {customDictionaryPath ?? "No file chosen"}
          </span>
          <button
            type="button"
            onClick={pickDictionary}
            className="rounded-md border border-border px-3 py-1.5 text-sm text-text transition-colors hover:border-primary"
          >
            Browse…
          </button>
        </div>
      )}
    </div>
  );
}

function NoIdeaConfig() {
  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm leading-relaxed text-text-muted">
        We'll try every possible combination up to 16 characters long. This is
        the most thorough option, but it can take a very long time and may never
        finish.
      </p>
      <div className="rounded-md border border-border bg-card p-4 text-sm">
        <span className="text-text-muted">Length:</span> 1–16 characters
        <span className="ml-4 text-text-muted">Characters:</span> all printable
      </div>
    </div>
  );
}

export function ConfigureView() {
  const knowledge = useRecovery((s) => s.knowledge);
  const subKnowledge = useRecovery((s) => s.subKnowledge);
  const history = useRecovery((s) => s.history);
  const partA = useRecovery((s) => s.partA);
  const partB = useRecovery((s) => s.partB);
  const dictionaryChoice = useRecovery((s) => s.dictionaryChoice);
  const customDictionaryPath = useRecovery((s) => s.customDictionaryPath);
  const backToKnowledge = useRecovery((s) => s.backToKnowledge);
  const startRecovery = useRecovery((s) => s.startRecovery);

  const canStart =
    knowledge !== "partial" ||
    subKnowledge === "11" ||
    (subKnowledge === "12" && history.trim().length > 0) ||
    (subKnowledge === "13" && partA.trim().length > 0 && partB.trim().length > 0);
  const needsDictionary =
    knowledge === "common" && dictionaryChoice === "custom" && !customDictionaryPath;

  return (
    <div className="flex flex-1 flex-col gap-5 overflow-y-auto p-6">
      <h2 className="text-lg font-semibold">Configure the attempt</h2>

      <div className="flex-1">
        {knowledge === "partial" && <PartialConfig />}
        {knowledge === "common" && <CommonConfig />}
        {knowledge === "none" && <NoIdeaConfig />}
      </div>

      <div className="flex justify-between border-t border-border pt-4">
        <button
          type="button"
          onClick={backToKnowledge}
          className="rounded-md border border-border px-6 py-2.5 text-sm text-text transition-colors hover:border-primary"
        >
          Back
        </button>
        <button
          type="button"
          disabled={!canStart || needsDictionary}
          onClick={() => void startRecovery()}
          className="rounded-md bg-primary px-8 py-2.5 text-sm font-semibold text-bg transition-colors hover:bg-primary-hover disabled:cursor-not-allowed disabled:opacity-40"
        >
          Start recovery
        </button>
      </div>
    </div>
  );
}
