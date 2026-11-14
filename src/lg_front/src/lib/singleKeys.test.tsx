import { act, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { useSingleKeys } from './singleKeys';

/** One reader of the switch, as the shell or a page is. */
function Reader({ name, userId }: { name: string; userId: string | null }) {
  const [on, set] = useSingleKeys(userId);
  return (
    <button onClick={() => set(!on)}>
      {name}: {on ? 'on' : 'off'}
    </button>
  );
}

const press = (name: RegExp) => act(() => screen.getByRole('button', { name }).click());

afterEach(() => {
  window.localStorage.clear();
});

describe('the single-key switch', () => {
  it('is on by default, kept per user, and one switch for everything that reads it', () => {
    render(
      <>
        <Reader name="shell" userId="u-1" />
        <Reader name="page" userId="u-1" />
        <Reader name="someone else" userId="u-2" />
      </>,
    );
    expect(screen.getByRole('button', { name: 'shell: on' })).toBeInTheDocument();
    press(/^page/);
    // Switched off on the page: the shell follows at once, the other user does not.
    expect(screen.getByRole('button', { name: 'shell: off' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'page: off' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'someone else: on' })).toBeInTheDocument();
    expect(window.localStorage.getItem('lg-sotf.single-keys.u-1')).toBe('off');
    expect(window.localStorage.getItem('lg-sotf.single-keys.u-2')).toBeNull();
    press(/^shell/);
    expect(screen.getByRole('button', { name: 'page: on' })).toBeInTheDocument();
    expect(window.localStorage.getItem('lg-sotf.single-keys.u-1')).toBe('on');
  });

  it('reads the stored choice of the user', () => {
    window.localStorage.setItem('lg-sotf.single-keys.u-1', 'off');
    render(<Reader name="shell" userId="u-1" />);
    expect(screen.getByRole('button', { name: 'shell: off' })).toBeInTheDocument();
  });

  it('lasts for the page without a user account, and where the browser keeps nothing', () => {
    const view = render(<Reader name="shell" userId={null} />);
    press(/^shell/);
    expect(screen.getByRole('button', { name: 'shell: off' })).toBeInTheDocument();
    expect(window.localStorage).toHaveLength(0);
    press(/^shell/);
    expect(screen.getByRole('button', { name: 'shell: on' })).toBeInTheDocument();
    view.unmount();

    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    render(<Reader name="page" userId="u-3" />);
    press(/^page/);
    expect(screen.getByRole('button', { name: 'page: off' })).toBeInTheDocument();
    // Once the browser keeps it again, the stored value is what counts.
    vi.restoreAllMocks();
    press(/^page/);
    expect(window.localStorage.getItem('lg-sotf.single-keys.u-3')).toBe('on');
    expect(screen.getByRole('button', { name: 'page: on' })).toBeInTheDocument();
  });
});
