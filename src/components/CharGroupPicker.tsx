import type { CharGroup } from "../lib/charsets";
import { isCharSelected, toggleChar } from "../lib/charsets";

interface Props {
  label: string;
  chars: string;
  state: CharGroup;
  onChange: (patch: Partial<CharGroup>) => void;
  /** Custom label for a character (e.g. "space" for ' '). */
  display?: (char: string) => string;
}

/** Checkbox grid for one character group with a select-all toggle.
 *  Un-ticking select-all excludes the whole group from the charset. */
export function CharGroupPicker({ label, chars, state, onChange, display }: Props) {
  const allChecked = state.all;
  const isNone = !state.all && state.selected.length === 0;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium">{label}</span>
        <label className="flex cursor-pointer items-center gap-2 text-xs text-text-muted">
          <input
            type="checkbox"
            checked={allChecked}
            onChange={() =>
              onChange(
                allChecked
                  ? { all: false, selected: [] }
                  : { all: true, selected: [] },
              )
            }
            className="accent-primary"
          />
          Select all
        </label>
      </div>
      {isNone && (
        <p className="text-xs text-text-muted">
          This group is excluded. Ticking Select all (or any character) will
          include it again.
        </p>
      )}
      <div className="grid grid-cols-8 gap-1.5">
        {[...chars].map((char) => {
          const checked = isCharSelected(state, char);
          const key = char === " " ? "space" : char;
          return (
            <button
              key={key}
              type="button"
              onClick={() => onChange(toggleChar(state, chars, char))}
              className={`rounded border px-1 py-1.5 text-center font-mono text-xs transition-colors ${
                checked
                  ? "border-primary bg-primary/10 text-text"
                  : "border-border bg-bg text-text-muted hover:border-primary/60"
              }`}
            >
              {display ? display(char) : char}
            </button>
          );
        })}
      </div>
    </div>
  );
}
