import { Monitor, Moon, Rows3, Sun, type LucideIcon } from 'lucide-react';
import { useId } from 'react';

import { useDensity } from '../../theme/density';
import { useTheme, type ThemePreference } from '../../theme/theme';
import { cx } from './cx';

const THEME_OPTIONS: Array<{ value: ThemePreference; label: string; icon: LucideIcon }> = [
  { value: 'dark', label: 'Dark', icon: Moon },
  { value: 'light', label: 'Light', icon: Sun },
  { value: 'system', label: 'System', icon: Monitor },
];

/**
 * Theme choice as a radio group (Dark / Light / System): native radios, so
 * arrow keys move between the options. `showLabels` prints the words next to
 * the icons; without it the words are for screen readers and tooltips.
 */
export function ThemeSwitch({ showLabels = false, className }: { showLabels?: boolean; className?: string }) {
  const { preference, setPreference } = useTheme();
  const name = useId();
  return (
    <fieldset className={cx('inline-flex items-center rounded-control border border-subtle bg-raised p-0.5', className)}>
      <legend className="sr-only">Theme</legend>
      {THEME_OPTIONS.map(({ value, label, icon: Icon }) => (
        <label key={value} title={label} className="relative cursor-pointer">
          <input
            type="radio"
            name={name}
            value={value}
            checked={preference === value}
            onChange={() => setPreference(value)}
            className="peer sr-only"
          />
          <span
            className={cx(
              'flex h-7 items-center justify-center gap-1.5 rounded-tag text-xs font-medium text-secondary touch:min-h-11',
              showLabels ? 'px-2.5' : 'w-7 touch:min-w-11',
              'hover:text-fg peer-checked:bg-selected peer-checked:text-fg',
              'peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-focus',
            )}
          >
            <Icon className="h-4 w-4" strokeWidth={1.75} aria-hidden="true" />
            <span className={showLabels ? undefined : 'sr-only'}>{label}</span>
          </span>
        </label>
      ))}
    </fieldset>
  );
}

/** Table row density: compact by default; this toggle switches to comfortable rows. */
export function DensityToggle({ className }: { className?: string }) {
  const { density, setDensity } = useDensity();
  const comfortable = density === 'comfortable';
  return (
    <button
      type="button"
      aria-pressed={comfortable}
      onClick={() => setDensity(comfortable ? 'compact' : 'comfortable')}
      className={cx(
        'inline-flex h-8 items-center gap-2 rounded-control border px-2.5 text-ctl touch:min-h-11',
        comfortable ? 'border-link bg-selected text-fg' : 'border-control bg-raised text-secondary hover:bg-raised-2',
        className,
      )}
    >
      <Rows3 className="h-4 w-4" strokeWidth={1.75} aria-hidden="true" />
      Comfortable rows
    </button>
  );
}
