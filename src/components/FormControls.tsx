import { ReactNode } from "react";

interface RadioProps {
  checked: boolean;
  onChange: () => void;
  label?: ReactNode;
  className?: string;
}

export function Radio({ checked, onChange, label, className }: RadioProps) {
  const input = (
    <button
      type="button"
      role="radio"
      aria-checked={checked}
      onClick={onChange}
      className={`flex h-4 w-4 shrink-0 items-center justify-center rounded-full border-2 transition-colors ${
        checked
          ? "border-primary bg-primary"
          : "border-text-muted/50 bg-transparent hover:border-primary/60"
      } ${className ?? ""}`}
    >
      {checked && <span className="h-1.5 w-1.5 rounded-full bg-bg" />}
    </button>
  );

  if (!label) return input;

  return (
    <label className="flex cursor-pointer items-center gap-2">
      {input}
      {label}
    </label>
  );
}

interface CheckboxProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label?: ReactNode;
  className?: string;
}

export function Checkbox({ checked, onChange, label, className }: CheckboxProps) {
  const input = (
    <button
      type="button"
      role="checkbox"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className={`flex h-4 w-4 shrink-0 items-center justify-center rounded border transition-colors ${
        checked
          ? "border-primary bg-primary"
          : "border-text-muted/50 bg-transparent hover:border-primary/60"
      } ${className ?? ""}`}
    >
      {checked && (
        <svg
          viewBox="0 0 12 12"
          fill="none"
          className="h-2.5 w-2.5"
          stroke="currentColor"
          strokeWidth={2}
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M2.5 6L5 8.5L9.5 3.5" className="text-bg" />
        </svg>
      )}
    </button>
  );

  if (!label) return input;

  return (
    <label className="flex cursor-pointer items-center gap-2">
      {input}
      {label}
    </label>
  );
}

interface SwitchProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label?: ReactNode;
  description?: ReactNode;
  className?: string;
}

export function Switch({ checked, onChange, label, description, className }: SwitchProps) {
  return (
    <label className={`flex cursor-pointer items-center gap-3 ${className ?? ""}`}>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={`relative h-5 w-9 shrink-0 rounded-full transition-colors ${
          checked ? "bg-primary" : "bg-text-muted/30"
        }`}
      >
        <span
          className={`absolute top-0.5 left-0.5 h-4 w-4 rounded-full bg-bg shadow-sm transition-transform ${
            checked ? "translate-x-4" : ""
          }`}
        />
      </button>
      {(label || description) && (
        <span className="flex flex-col gap-0.5">
          {label && <span className="text-sm font-semibold">{label}</span>}
          {description && (
            <span className="text-xs text-text-muted">{description}</span>
          )}
        </span>
      )}
    </label>
  );
}
