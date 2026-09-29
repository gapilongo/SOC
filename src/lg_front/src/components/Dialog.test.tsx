import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { describe, expect, it } from 'vitest';

import { ConfirmDialog, Modal } from './Dialog';

function Harness() {
  const [open, setOpen] = useState(false);
  const [confirm, setConfirm] = useState(false);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>
        Open
      </button>
      <Modal open={open} onClose={() => setOpen(false)} title="Alert details">
        <button type="button" onClick={() => setConfirm(true)}>
          Reprocess
        </button>
        <ConfirmDialog open={confirm} title="Confirm" confirmLabel="Yes" onConfirm={() => setConfirm(false)} onCancel={() => setConfirm(false)}>
          Sure?
        </ConfirmDialog>
      </Modal>
    </>
  );
}

describe('Modal accessibility', () => {
  it('labels the dialog, moves focus in, traps Tab and restores focus on Escape', async () => {
    render(<Harness />);
    const opener = screen.getByRole('button', { name: 'Open' });
    await userEvent.click(opener);
    const dialog = screen.getByRole('dialog', { name: 'Alert details' });
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(screen.getByRole('button', { name: 'Close' })).toHaveFocus();
    await userEvent.tab();
    expect(screen.getByRole('button', { name: 'Reprocess' })).toHaveFocus();
    await userEvent.tab();
    expect(screen.getByRole('button', { name: 'Close' })).toHaveFocus();
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });

  it('closes only the innermost dialog on Escape', async () => {
    render(<Harness />);
    await userEvent.click(screen.getByRole('button', { name: 'Open' }));
    await userEvent.click(screen.getByRole('button', { name: 'Reprocess' }));
    expect(screen.getByRole('dialog', { name: 'Confirm' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Cancel' })).toHaveFocus();
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('dialog', { name: 'Confirm' })).not.toBeInTheDocument();
    expect(screen.getByRole('dialog', { name: 'Alert details' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Reprocess' })).toHaveFocus();
  });
});
