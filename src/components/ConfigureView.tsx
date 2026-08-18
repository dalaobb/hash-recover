import { useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { useRecovery, RuleLevel } from "../store/recovery";
import {
  buildCharset,
  GROUP_CHARS,
  GroupKey,
  hasCharsetSelection,
  maskLengths,
} from "../lib/charsets";
import { useT } from "../lib/i18n";
import { CharGroupPicker } from "./CharGroupPicker";
import { Radio, Switch } from "./FormControls";

const TABS = [
  { id: "length", key: "configure.tab.length" },
  { id: "edges", key: "configure.tab.edges" },
  { id: "lower", key: "configure.tab.lower" },
  { id: "upper", key: "configure.tab.upper" },
  { id: "digit", key: "configure.tab.digit" },
  { id: "special", key: "configure.tab.special" },
  { id: "overview", key: "configure.tab.overview" },
] as const;

type TabId = (typeof TABS)[number]["id"];

const RULE_LEVELS: {
  id: RuleLevel;
  labelKey:
    | "configure.rules.simple"
    | "configure.rules.deep"
    | "configure.rules.extreme";
  descKey:
    | "configure.rules.simpleDesc"
    | "configure.rules.deepDesc"
    | "configure.rules.extremeDesc";
}[] = [
  {
    id: "simple",
    labelKey: "configure.rules.simple",
    descKey: "configure.rules.simpleDesc",
  },
  {
    id: "deep",
    labelKey: "configure.rules.deep",
    descKey: "configure.rules.deepDesc",
  },
  {
    id: "extreme",
    labelKey: "configure.rules.extreme",
    descKey: "configure.rules.extremeDesc",
  },
];

const GROUP_KEYS: Record<
  GroupKey,
  | "configure.group.lower"
  | "configure.group.upper"
  | "configure.group.digit"
  | "configure.group.special"
> = {
  lower: "configure.group.lower",
  upper: "configure.group.upper",
  digit: "configure.group.digit",
  special: "configure.group.special",
};

const GROUP_TAB_KEYS: Record<
  GroupKey,
  | "configure.groupTab.lower"
  | "configure.groupTab.upper"
  | "configure.groupTab.digit"
  | "configure.groupTab.special"
> = {
  lower: "configure.groupTab.lower",
  upper: "configure.groupTab.upper",
  digit: "configure.groupTab.digit",
  special: "configure.groupTab.special",
};

const inputCls =
  "rounded-md border border-border bg-bg px-3 py-2 text-sm text-text outline-none focus:border-primary";

function LengthTab() {
  const maskConfig = useRecovery((s) => s.maskConfig);
  const setMaskConfig = useRecovery((s) => s.setMaskConfig);
  const t = useT();

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-2">
        <Radio
          checked={maskConfig.lengthMode === "fixed"}
          onChange={() => setMaskConfig({ lengthMode: "fixed" })}
          label={t("configure.length.exact")}
        />
        {maskConfig.lengthMode === "fixed" && (
          <div className="flex items-center gap-2 pl-6">
            <span className="text-sm text-text-muted">
              {t("configure.length.label")}
            </span>
            <input
              type="number"
              min={1}
              max={32}
              value={maskConfig.fixedLength}
              onChange={(e) =>
                setMaskConfig({
                  fixedLength: Math.max(1, Number(e.target.value) || 1),
                })
              }
              className={`${inputCls} w-24`}
            />
          </div>
        )}
      </div>

      <Radio
        checked={maskConfig.lengthMode === "range"}
        onChange={() => setMaskConfig({ lengthMode: "range" })}
        label={t("configure.length.between")}
      />
      {maskConfig.lengthMode === "range" && (
        <div className="flex items-center gap-2 pl-6">
          <span className="text-sm text-text-muted">
            {t("configure.length.from")}
          </span>
          <input
            type="number"
            min={1}
            max={32}
            value={maskConfig.minLength}
            onChange={(e) =>
              setMaskConfig({
                minLength: Math.max(1, Number(e.target.value) || 1),
              })
            }
            className={`${inputCls} w-24`}
          />
          <span className="text-sm text-text-muted">
            {t("configure.length.to")}
          </span>
          <input
            type="number"
            min={1}
            max={32}
            value={maskConfig.maxLength}
            onChange={(e) =>
              setMaskConfig({
                maxLength: Math.max(1, Number(e.target.value) || 1),
              })
            }
            className={`${inputCls} w-24`}
          />
        </div>
      )}

      <Radio
        checked={maskConfig.lengthMode === "unknown"}
        onChange={() => setMaskConfig({ lengthMode: "unknown" })}
        label={t("configure.length.unknown")}
      />
    </div>
  );
}

function EdgesTab() {
  const maskConfig = useRecovery((s) => s.maskConfig);
  const setMaskConfig = useRecovery((s) => s.setMaskConfig);
  const t = useT();

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-1.5">
        <label className="text-sm text-text-muted" htmlFor="prefix">
          {t("configure.edges.startsWith")}
        </label>
        <input
          id="prefix"
          value={maskConfig.prefix}
          onChange={(e) => setMaskConfig({ prefix: e.target.value })}
          placeholder={t("configure.edges.startsWithPlaceholder")}
          className={`${inputCls} max-w-sm font-mono`}
        />
      </div>
      <div className="flex flex-col gap-1.5">
        <label className="text-sm text-text-muted" htmlFor="suffix">
          {t("configure.edges.endsWith")}
        </label>
        <input
          id="suffix"
          value={maskConfig.suffix}
          onChange={(e) => setMaskConfig({ suffix: e.target.value })}
          placeholder={t("configure.edges.endsWithPlaceholder")}
          className={`${inputCls} max-w-sm font-mono`}
        />
      </div>
      <p className="text-xs text-text-muted">{t("configure.edges.note")}</p>
    </div>
  );
}

function GroupTab({ group }: { group: GroupKey }) {
  const maskConfig = useRecovery((s) => s.maskConfig);
  const setCharGroup = useRecovery((s) => s.setCharGroup);
  const t = useT();
  const chars = GROUP_CHARS[group];

  return (
    <CharGroupPicker
      label={t(GROUP_TAB_KEYS[group])}
      chars={chars}
      state={maskConfig[group]}
      onChange={(patch) => setCharGroup(group, patch)}
      display={(c) => (c === " " ? t("charGroup.space") : c)}
    />
  );
}

function OverviewTab() {
  const maskConfig = useRecovery((s) => s.maskConfig);
  const { min, max } = maskLengths(maskConfig);
  const charset = buildCharset(maskConfig);
  const t = useT();

  const groups: { key: GroupKey; count: number }[] = (
    ["lower", "upper", "digit", "special"] as GroupKey[]
  ).map((key) => ({ key, count: GROUP_CHARS[key].length }));

  return (
    <div className="flex flex-col gap-4 text-sm">
      <div className="rounded-md border border-border bg-bg p-4">
        <table className="w-full">
          <tbody className="divide-y divide-border">
            <tr>
              <td className="py-1.5 text-text-muted">
                {t("configure.overview.length")}
              </td>
              <td className="py-1.5 text-right">
                {min === max
                  ? t("configure.overview.characters", { count: min })
                  : t("configure.overview.range", { min, max })}
              </td>
            </tr>
            <tr>
              <td className="py-1.5 text-text-muted">
                {t("configure.overview.startsWith")}
              </td>
              <td className="py-1.5 text-right font-mono">
                {maskConfig.prefix || "—"}
              </td>
            </tr>
            <tr>
              <td className="py-1.5 text-text-muted">
                {t("configure.overview.endsWith")}
              </td>
              <td className="py-1.5 text-right font-mono">
                {maskConfig.suffix || "—"}
              </td>
            </tr>
            {groups.map(({ key, count }) => {
              const g = maskConfig[key];
              const full = g.all;
              const none = !g.all && g.selected.length === 0;
              return (
                <tr key={key}>
                  <td className="py-1.5 text-text-muted">
                    {t(GROUP_KEYS[key])}
                  </td>
                  <td className="py-1.5 text-right">
                    {full
                      ? t("configure.overview.all", { count })
                      : none
                        ? t("configure.overview.excluded")
                        : t("configure.overview.of", {
                            selected: g.selected.length,
                            count,
                          })}
                  </td>
                </tr>
              );
            })}
            <tr>
              <td className="py-1.5 text-text-muted">
                {t("configure.overview.characterSet")}
              </td>
              <td className="py-1.5 text-right font-mono">
                {charset === "all"
                  ? t("configure.overview.allPrintable")
                  : charset}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p className="text-xs leading-relaxed text-text-muted">
        {t("configure.overview.note")}
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
  const ruleLevel = useRecovery((s) => s.ruleLevel);
  const setRuleLevel = useRecovery((s) => s.setRuleLevel);
  const t = useT();

  if (subKnowledge === "12") {
    return (
      <div className="flex flex-col gap-2">
        <label className="text-sm text-text-muted" htmlFor="history">
          {t("configure.history.label")}
        </label>
        <textarea
          id="history"
          rows={6}
          value={history}
          onChange={(e) => setHistory(e.target.value)}
          placeholder={"password123\npassword!\npassw0rd"}
          className={`${inputCls} resize-y font-mono`}
        />
        <p className="text-xs text-text-muted">{t("configure.history.note")}</p>

        <div className="mt-1 flex flex-col gap-1.5">
          <span className="text-sm text-text-muted">
            {t("configure.rules.level")}
          </span>
          <div className="flex flex-col gap-1.5">
            {RULE_LEVELS.map((level) => {
              const selected = ruleLevel === level.id;
              return (
                <label
                  key={level.id}
                  className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 text-sm transition-colors ${
                    selected
                      ? "border-primary bg-card"
                      : "border-border bg-card hover:border-primary/60"
                  }`}
                >
                  <Radio
                    checked={selected}
                    onChange={() => setRuleLevel(level.id)}
                    className="mt-0.5"
                  />
                  <span>
                    <span className="font-semibold">{t(level.labelKey)}</span>
                    <span className="block text-xs text-text-muted">
                      {t(level.descKey)}
                    </span>
                  </span>
                </label>
              );
            })}
          </div>
        </div>
      </div>
    );
  }

  if (subKnowledge === "13") {
    return (
      <div className="flex flex-col gap-4">
        <div className="flex flex-col gap-1.5">
          <label className="text-sm text-text-muted" htmlFor="partA">
            {t("configure.partA.label")}
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
            {t("configure.partB.label")}
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
        <p className="text-xs text-text-muted">{t("configure.parts.note")}</p>
      </div>
    );
  }

  // subKnowledge === "11" (or unset): character/length tabs.
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap gap-1 rounded-md border border-border bg-card p-1">
        {TABS.map((tabDef) => (
          <button
            key={tabDef.id}
            type="button"
            onClick={() => setTab(tabDef.id)}
            className={`rounded px-3 py-1.5 text-sm transition-colors ${
              tab === tabDef.id
                ? "bg-primary font-semibold text-bg"
                : "text-text-muted hover:text-text"
            }`}
          >
            {t(tabDef.key)}
          </button>
        ))}
      </div>
      <div className="rounded-lg border border-border bg-card p-5">
        {tab === "length" && <LengthTab />}
        {tab === "edges" && <EdgesTab />}
        {tab === "lower" && <GroupTab group="lower" />}
        {tab === "upper" && <GroupTab group="upper" />}
        {tab === "digit" && <GroupTab group="digit" />}
        {tab === "special" && <GroupTab group="special" />}
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
  const useRules = useRecovery((s) => s.useRules);
  const setUseRules = useRecovery((s) => s.setUseRules);
  const t = useT();

  async function pickDictionary() {
    const file = await open({
      multiple: false,
      title: t("configure.common.chooseWordList"),
      filters: [{ name: t("configure.common.wordLists"), extensions: ["txt"] }],
    });
    if (typeof file === "string") {
      setCustomDictionaryPath(file);
    }
  }

  return (
    <div className="flex flex-col gap-2.5">
      <label className="flex items-center gap-2.5 rounded-lg border border-border bg-card p-4 text-sm">
        <Radio
          checked={dictionaryChoice !== "custom"}
          onChange={() => setDictionaryChoice("default")}
        />
        <span>
          <span className="font-semibold">{t("configure.common.builtin")}</span>
          <span className="block text-xs text-text-muted">
            {t("configure.common.builtinDesc")}
          </span>
        </span>
      </label>

      <label className="flex items-center gap-2.5 rounded-lg border border-border bg-card p-4 text-sm">
        <Radio
          checked={dictionaryChoice === "custom"}
          onChange={() => setDictionaryChoice("custom")}
        />
        <span>
          <span className="font-semibold">{t("configure.common.custom")}</span>
          <span className="block text-xs text-text-muted">
            {t("configure.common.customDesc")}
          </span>
        </span>
      </label>

      {dictionaryChoice === "custom" && (
        <div className="flex items-center gap-3 pl-7">
          <span className="max-w-xs truncate font-mono text-xs text-text-muted">
            {customDictionaryPath ?? t("configure.common.noFile")}
          </span>
          <button
            type="button"
            onClick={pickDictionary}
            className="rounded-md border border-border px-3 py-1.5 text-sm text-text transition-colors hover:border-primary"
          >
            {t("configure.common.browse")}
          </button>
        </div>
      )}

      <div className="rounded-lg border border-border bg-bg p-4">
        <Switch
          checked={useRules}
          onChange={(checked) => setUseRules(checked)}
          label={t("configure.rules.dictionaryToggle")}
          description={t("configure.rules.dictionaryToggleDesc")}
        />
      </div>
    </div>
  );
}

function NoIdeaConfig() {
  const t = useT();

  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm leading-relaxed text-text-muted">
        {t("configure.noIdea.note")}
      </p>
      <div className="rounded-md border border-border bg-card p-4 text-sm">
        <span className="text-text-muted">{t("configure.noIdea.length")}</span>{" "}
        {t("configure.noIdea.oneTo16")}
        <span className="ml-4 text-text-muted">
          {t("configure.noIdea.characters")}
        </span>{" "}
        {t("configure.noIdea.allPrintable")}
      </div>
    </div>
  );
}

export function ConfigureView() {
  const knowledge = useRecovery((s) => s.knowledge);
  const subKnowledge = useRecovery((s) => s.subKnowledge);
  const maskConfig = useRecovery((s) => s.maskConfig);
  const history = useRecovery((s) => s.history);
  const partA = useRecovery((s) => s.partA);
  const partB = useRecovery((s) => s.partB);
  const dictionaryChoice = useRecovery((s) => s.dictionaryChoice);
  const customDictionaryPath = useRecovery((s) => s.customDictionaryPath);
  const backToKnowledge = useRecovery((s) => s.backToKnowledge);
  const startRecovery = useRecovery((s) => s.startRecovery);
  const t = useT();

  const canStart =
    knowledge !== "partial" ||
    (subKnowledge === "11" && hasCharsetSelection(maskConfig)) ||
    (subKnowledge === "12" && history.trim().length > 0) ||
    (subKnowledge === "13" &&
      partA.trim().length > 0 &&
      partB.trim().length > 0);
  const needsDictionary =
    knowledge === "common" &&
    dictionaryChoice === "custom" &&
    !customDictionaryPath;

  return (
    <div className="flex flex-1 flex-col gap-5 overflow-y-auto p-6">
      <h2 className="text-lg font-semibold">{t("configure.title")}</h2>

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
          {t("configure.back")}
        </button>
        <button
          type="button"
          disabled={!canStart || needsDictionary}
          onClick={() => void startRecovery()}
          className="rounded-md bg-primary px-8 py-2.5 text-sm font-semibold text-bg transition-colors hover:bg-primary-hover disabled:cursor-not-allowed disabled:opacity-40"
        >
          {t("configure.start")}
        </button>
      </div>
    </div>
  );
}
