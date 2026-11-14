import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { DensityToggle, ThemeSwitch } from '../components/ui';
import { readPref, writePref } from '../lib/prefs';
import { DensityProvider, parseDensity, useDensity } from './density';
import { applyTheme, parseThemePreference, resolveTheme, ThemeProvider, useTheme } from './theme';

/** A controllable prefers-color-scheme: dark media query. */
function mockSystemTheme(dark: boolean) {
  const listeners = new Set<(e: MediaQueryListEvent) => void>();
  const media = {
    matches: dark,
    media: '(prefers-color-scheme: dark)',
    addEventListener: (_: string, fn: (e: MediaQueryListEvent) => void) => listeners.add(fn),
    removeEventListener: (_: string, fn: (e: MediaQueryListEvent) => void) => listeners.delete(fn),
  };
  vi.stubGlobal('matchMedia', vi.fn(() => media));
  return {
    set(next: boolean) {
      media.matches = next;
      act(() => listeners.forEach((fn) => fn({ matches: next } as MediaQueryListEvent)));
    },
    listeners,
  };
}

function ThemeProbe() {
  const { preference, resolved } = useTheme();
  return (
    <p>
      {preference}/{resolved}
    </p>
  );
}

function DensityProbe() {
  return <p>density {useDensity().density}</p>;
}

beforeEach(() => {
  window.localStorage.clear();
  delete document.documentElement.dataset.theme;
  delete document.documentElement.dataset.density;
});
afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

describe('theme helpers', () => {
  it('parses a stored preference, defaulting to the system setting', () => {
    expect(parseThemePreference('light')).toBe('light');
    expect(parseThemePreference('system')).toBe('system');
    expect(parseThemePreference('dark')).toBe('dark');
    expect(parseThemePreference('purple')).toBe('system');
    expect(parseThemePreference(null)).toBe('system');
  });

  it('resolves "system" from the operating system setting: light unless it asks for dark', () => {
    expect(resolveTheme('system', true)).toBe('dark');
    expect(resolveTheme('system', false)).toBe('light');
    expect(resolveTheme('light', true)).toBe('light');
    expect(resolveTheme('dark', false)).toBe('dark');
  });

  it('sets data-theme on the given root', () => {
    const el = document.createElement('div');
    applyTheme('light', el);
    expect(el.dataset.theme).toBe('light');
  });
});

describe('ThemeProvider and ThemeSwitch', () => {
  it('follows the system without a stored choice', () => {
    mockSystemTheme(true);
    const { unmount } = render(
      <ThemeProvider>
        <ThemeProbe />
      </ThemeProvider>,
    );
    expect(screen.getByText('system/dark')).toBeInTheDocument();
    expect(document.documentElement.dataset.theme).toBe('dark');
    unmount();

    mockSystemTheme(false);
    render(
      <ThemeProvider>
        <ThemeProbe />
      </ThemeProvider>,
    );
    expect(screen.getByText('system/light')).toBeInTheDocument();
    expect(document.documentElement.dataset.theme).toBe('light');
    // Following the system is not a choice: nothing is stored until the user picks a theme.
    expect(readPref('theme')).toBeNull();
  });

  it('switches theme, persists the choice and restores it', async () => {
    mockSystemTheme(true);
    const { unmount } = render(
      <ThemeProvider>
        <ThemeSwitch />
        <ThemeProbe />
      </ThemeProvider>,
    );
    const group = screen.getByRole('group', { name: 'Theme' });
    expect(group).toBeInTheDocument();
    expect(screen.getByRole('radio', { name: 'System' })).toBeChecked();
    expect(document.documentElement.dataset.theme).toBe('dark');

    await userEvent.click(screen.getByRole('radio', { name: 'Light' }));
    expect(document.documentElement.dataset.theme).toBe('light');
    expect(readPref('theme')).toBe('light');
    unmount();

    render(
      <ThemeProvider>
        <ThemeProbe />
      </ThemeProvider>,
    );
    expect(screen.getByText('light/light')).toBeInTheDocument();
  });

  it('moves between the options with the arrow keys', async () => {
    mockSystemTheme(false);
    render(
      <ThemeProvider>
        <ThemeSwitch showLabels />
      </ThemeProvider>,
    );
    expect(screen.getByText('Light')).toBeVisible();
    screen.getByRole('radio', { name: 'System' }).focus();
    await userEvent.keyboard('{ArrowRight}');
    expect(screen.getByRole('radio', { name: 'Light' })).toBeChecked();
    expect(document.documentElement.dataset.theme).toBe('light');
    await userEvent.keyboard('{ArrowRight}');
    expect(screen.getByRole('radio', { name: 'Dark' })).toBeChecked();
    expect(document.documentElement.dataset.theme).toBe('dark');
  });

  it('follows the operating system in System mode, including later changes', async () => {
    const system = mockSystemTheme(false);
    writePref('theme', 'system');
    const { unmount } = render(
      <ThemeProvider>
        <ThemeProbe />
      </ThemeProvider>,
    );
    expect(screen.getByText('system/light')).toBeInTheDocument();
    expect(document.documentElement.dataset.theme).toBe('light');
    system.set(true);
    expect(screen.getByText('system/dark')).toBeInTheDocument();
    expect(document.documentElement.dataset.theme).toBe('dark');
    unmount();
    expect(system.listeners.size).toBe(0);
  });

  it('works without matchMedia and without storage', async () => {
    vi.stubGlobal('matchMedia', undefined);
    const getItem = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    const setItem = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    render(
      <ThemeProvider>
        <ThemeSwitch />
        <ThemeProbe />
      </ThemeProvider>,
    );
    // Nothing to ask and nothing stored: light, the default of the token file.
    expect(screen.getByText('system/light')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('radio', { name: 'Dark' }));
    expect(screen.getByText('dark/dark')).toBeInTheDocument();
    expect(getItem).toHaveBeenCalled();
    expect(setItem).toHaveBeenCalled();
  });

  it('refuses useTheme outside the provider', () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    expect(() => render(<ThemeProbe />)).toThrow(/ThemeProvider/);
  });
});

describe('table density', () => {
  it('parses the stored value, defaulting to compact', () => {
    expect(parseDensity('comfortable')).toBe('comfortable');
    expect(parseDensity('dense')).toBe('dense');
    expect(parseDensity('cosy')).toBe('compact');
    expect(parseDensity(null)).toBe('compact');
  });

  it('is compact by default and toggles to comfortable, persisted', async () => {
    const { unmount } = render(
      <DensityProvider>
        <DensityToggle />
        <DensityProbe />
      </DensityProvider>,
    );
    const toggle = screen.getByRole('button', { name: 'Comfortable rows' });
    expect(toggle).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByText('density compact')).toBeInTheDocument();
    expect(document.documentElement.dataset.density).toBe('compact');

    await userEvent.click(toggle);
    expect(toggle).toHaveAttribute('aria-pressed', 'true');
    expect(document.documentElement.dataset.density).toBe('comfortable');
    expect(readPref('density')).toBe('comfortable');
    unmount();

    render(
      <DensityProvider>
        <DensityToggle />
      </DensityProvider>,
    );
    await userEvent.click(screen.getByRole('button', { name: 'Comfortable rows' }));
    expect(document.documentElement.dataset.density).toBe('compact');
  });

  it('stays compact without a provider', () => {
    render(<DensityProbe />);
    expect(screen.getByText('density compact')).toBeInTheDocument();
  });
});
