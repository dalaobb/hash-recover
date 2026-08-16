/**
 * Character sets and mask helpers for the "know the length and characters"
 * flow. "None selected" always means "all characters" (per the product spec),
 * so a character group is never empty.
 */

export const LOWER = "abcdefghijklmnopqrstuvwxyz";
export const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
export const DIGIT = "0123456789";
export const SPECIAL = ` !"#$%&'()*+,-./:;<=>?@[\\]^_\`{|}~`;

export interface CharGroup {
  /** The whole group is allowed. */
  all: boolean;
  /** Explicit subset when `all` is false and the user deselected some chars. */
  selected: string[];
}

export type GroupKey = "lower" | "upper" | "digit" | "special";

export const GROUP_CHARS: Record<GroupKey, string> = {
  lower: LOWER,
  upper: UPPER,
  digit: DIGIT,
  special: SPECIAL,
};

export interface MaskConfig {
  lengthMode: "fixed" | "range" | "unknown";
  fixedLength: number;
  minLength: number;
  maxLength: number;
  prefix: string;
  suffix: string;
  lower: CharGroup;
  upper: CharGroup;
  digit: CharGroup;
  special: CharGroup;
}

export function defaultMaskConfig(): MaskConfig {
  return {
    lengthMode: "unknown",
    fixedLength: 8,
    minLength: 4,
    maxLength: 8,
    prefix: "",
    suffix: "",
    lower: { all: true, selected: [] },
    upper: { all: true, selected: [] },
    digit: { all: true, selected: [] },
    special: { all: true, selected: [] },
  };
}

export function isCharSelected(group: CharGroup, char: string): boolean {
  return group.all || group.selected.includes(char);
}

export function toggleChar(group: CharGroup, full: string, char: string): CharGroup {
  const all = [...full];
  if (group.all) {
    // Everything is currently selected; deselecting this char becomes explicit.
    return { all: false, selected: all.filter((c) => c !== char) };
  }
  if (group.selected.includes(char)) {
    return { all: false, selected: group.selected.filter((c) => c !== char) };
  }
  const selected = [...group.selected, char].sort();
  return selected.length === all.length
    ? { all: true, selected: [] }
    : { all: false, selected };
}

function isFull(group: CharGroup): boolean {
  return group.all;
}

/** The group contributes no characters (select-all was un-ticked). */
function isNone(group: CharGroup): boolean {
  return !group.all && group.selected.length === 0;
}

function groupString(group: CharGroup, full: string): string {
  if (group.all) return full;
  if (isNone(group)) return "";
  return group.selected.join("");
}

/** Effective charset for the mask, or "all" when every group is fully allowed
 *  (or none is allowed, as a safety net so the attack never runs empty). */
export function buildCharset(config: MaskConfig): string {
  const keys: GroupKey[] = ["lower", "upper", "digit", "special"];
  if (keys.every((k) => isFull(config[k]))) {
    return "all";
  }
  const union = keys.map((k) => groupString(config[k], GROUP_CHARS[k])).join("");
  if (!union) {
    return "all";
  }
  return [...new Set(union)].join("");
}

export function maskLengths(config: MaskConfig): { min: number; max: number } {
  switch (config.lengthMode) {
    case "fixed":
      return { min: config.fixedLength, max: config.fixedLength };
    case "range":
      return { min: config.minLength, max: config.maxLength };
    case "unknown":
      return { min: 1, max: 16 };
  }
}
