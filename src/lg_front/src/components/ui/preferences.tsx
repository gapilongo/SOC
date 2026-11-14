import { Monitor, Moon, Rows3, Sun, type LucideIcon } from 'lucide-react';
import { useId } from 'react';

import { useDensity } from '../../theme/density';
import { useTheme, type ThemePreference } from '../../theme/theme';
import { cx } from './cx';

const THEME_OPTIONS: Array<{ value: ThemePreference; label: string; icon: LucideIcon }> = [
  { value: 'system', label: 'System', icon: Monitor },
  { value: 'light', label: 'Light', icon: Sun },
  { value: 'dark', label: 'Dark', icon: Moon },
];

/**
 * Theme choice as a radio group (System / Light / Dark): native radios, so
 * arrow keys move between the options. `showLabels` prints the words next to
 * the icons; without it the words are for screen readers and tooltips.
 */
export function ThemeSwitch({ showLabels = false, className }: { showLabels?: boolean; className?: string }) {
  const { preference, setPreference } = useTheme();
  const name = useId();
  return (
    <fieldset className={cx('inline-flex items-stretch overflow-hidden rounded-control border border-control bg-raised', className)}>
      <legend className="sr-only">Theme</legend>
      {THEME_OPTIONS.map(({ value, label, icon: Icon }) => (
        <label key={value} title={label} className="relative cursor-pointer border-l border-strong first-of-type:border-l-0">
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
              'flex h-full min-h-ctl-sm items-center justify-center gap-1.5 text-xs font-medium text-secondary touch:min-h-ctl-touch',
              showLabels ? 'px-2.5' : 'w-ctl touch:min-w-ctl-touch',
              'hover:bg-raised-2 hover:text-fg peer-checked:bg-fg peer-checked:text-canvas',
              'peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:-outline-offset-2 peer-focus-visible:outline-focus',
            )}
          >
            <Icon className="h-3.5 w-3.5" strokeWidth={1.5} aria-hidden="true" />
            <span className={showLabels ? undefined : 'sr-only'}>{label}</span>
          </span>
        </label>
      ))}
    </fieldset>
  );
}

/** Table row density: compact (28 px) by default; this toggle switches to comfortable, two-line rows (44 px). */
export function DensityToggle({ className }: { className?: string }) {
  const { density, setDensity } = useDensity();
  const comfortable = density === 'comfortable';
  return (
    <button
      type="button"
      aria-pressed={comfortable}
      onClick={() => setDensity(comfortable ? 'compact' : 'comfortable')}
      className={cx(
        'inline-flex h-ctl items-center gap-1.5 rounded-control border px-2.5 text-ctl font-medium touch:min-h-ctl-touch',
        comfortable ? 'border-fg bg-fg text-canvas' : 'border-control bg-raised text-fg hover:bg-raised-2',
        className,
      )}
    >
      <Rows3 className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />
      Comfortable rows
    </button>
  );
}
