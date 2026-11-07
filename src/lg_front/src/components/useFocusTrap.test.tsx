import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useRef, useState, type ReactNode } from 'react';
import { describe, expect, it, vi } from 'vitest';

import { useFocusTrap, type FocusTrapOptions } from './useFocusTrap';

function Trap({ open, options, children }: { open: boolean; options?: FocusTrapOptions; children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  useFocusTrap(ref, open, options);
  return open ? (
    <div ref={ref} tabIndex={-1} data-testid="panel">
      {children}
    </div>
  ) : null;
}

function Harness({ options, children }: { options?: FocusTrapOptions; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>
        open
      </button>
      <button type="button">outside</button>
      <Trap open={open} options={{ ...options, onEscape: options?.onEscape ?? (() => setOpen(false)) }}>
        {children}
      </Trap>
    </>
  );
}

describe('useFocusTrap', () => {
  it('focuses the data-autofocus element, wraps Tab and restores focus', async () => {
    const user = userEvent.setup();
    render(
      <Harness>
        <button type="button">first</button>
        <button type="button" data-autofocus>
          second
        </button>
        <details>
          <summary>more</summary>
          <button type="button">hidden in details</button>
        </details>
        <div hidden>
          <button type="button">hidden</button>
        </div>
      </Harness>,
    );
    const opener = screen.getByRole('button', { name: 'open' });
    await user.click(opener);
    expect(screen.getByRole('button', { name: 'second' })).toHaveFocus();
    await user.tab();
    expect(screen.getByText('more')).toHaveFocus();
    // The button inside the closed <details> and the hidden one are skipped: wrap to the first.
    await user.tab();
    expect(screen.getByRole('button', { name: 'first' })).toHaveFocus();
    await user.tab({ shift: true });
    expect(screen.getByText('more')).toHaveFocus();
    await user.keyboard('{Escape}');
    expect(screen.queryByTestId('panel')).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });

  it('brings focus back inside when it escaped the panel', async () => {
    const user = userEvent.setup();
    render(
      <Harness>
        <button type="button">only</button>
      </Harness>,
    );
    await user.click(screen.getByRole('button', { name: 'open' }));
    screen.getByRole('button', { name: 'outside' }).focus();
    await user.tab();
    expect(screen.getByRole('button', { name: 'only' })).toHaveFocus();
    screen.getByRole('button', { name: 'outside' }).focus();
    await user.tab({ shift: true });
    expect(screen.getByRole('button', { name: 'only' })).toHaveFocus();
  });

  it('focuses the panel itself when nothing inside is focusable, and keeps Tab there', async () => {
    const user = userEvent.setup();
    render(
      <Harness>
        <p>Nothing to press</p>
      </Harness>,
    );
    await user.click(screen.getByRole('button', { name: 'open' }));
    expect(screen.getByTestId('panel')).toHaveFocus();
    await user.tab();
    expect(screen.getByTestId('panel')).toHaveFocus();
  });

  it('can leave focus where it is, ignore Escape and lock scrolling while open', async () => {
    const user = userEvent.setup();
    function Locked({ open }: { open: boolean }) {
      return (
        <Trap open={open} options={{ restoreFocus: false, lockScroll: true }}>
          <button type="button">inside</button>
        </Trap>
      );
    }
    document.body.style.overflow = 'auto';
    const { rerender } = render(<Locked open />);
    expect(document.body.style.overflow).toBe('hidden');
    // No onEscape: Escape does nothing.
    await user.keyboard('{Escape}');
    expect(screen.getByRole('button', { name: 'inside' })).toBeInTheDocument();
    rerender(<Locked open={false} />);
    expect(document.body.style.overflow).toBe('auto');
    expect(document.body).toHaveFocus();
  });

  it('lets only the innermost (last opened) trap handle keys', async () => {
    const user = userEvent.setup();
    const outer = vi.fn();
    const inner = vi.fn();
    const nested = (innerOpen: boolean) => (
      <Trap open options={{ onEscape: outer }}>
        <button type="button">outer</button>
        <Trap open={innerOpen} options={{ onEscape: inner }}>
          <button type="button">inner</button>
        </Trap>
      </Trap>
    );
    const { rerender } = render(nested(false));
    rerender(nested(true));
    expect(screen.getByRole('button', { name: 'inner' })).toHaveFocus();
    await user.keyboard('{Escape}');
    expect(inner).toHaveBeenCalledTimes(1);
    expect(outer).not.toHaveBeenCalled();
  });
});
