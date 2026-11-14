import { render, screen } from '@testing-library/react';
import { lazy, useEffect } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { SessionProvider } from '../auth/AuthContext';
import { contribute, defineSlot } from '../core/slots';
import { fakeApi, signedInSession } from '../test/helpers';
import { ExtensionsProvider, SlotOutlet } from './Slot';

const GREETING = defineSlot<{ name: string }>('test.greeting');
const OTHER = defineSlot('test.other');

const Hello = ({ name }: { name: string }) => <p>Hello {name}</p>;
const Bye = ({ name }: { name: string }) => <p>Bye {name}</p>;
const Broken = (): never => {
  throw new Error('contribution failed');
};

async function renderSlot(contributions: Parameters<typeof ExtensionsProvider>[0]['contributions'], role = 'analyst') {
  const session = await signedInSession(fakeApi(() => ({})).api, { role });
  return render(
    <SessionProvider session={session}>
      <ExtensionsProvider contributions={contributions}>
        <SlotOutlet slot={GREETING} props={{ name: 'Ada' }} empty={<p>nobody</p>} pending={<p>loading</p>} />
      </ExtensionsProvider>
    </SessionProvider>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('SlotOutlet', () => {
  it('renders what the owner gives for an empty slot', async () => {
    await renderSlot([contribute(OTHER, () => <p>elsewhere</p>)]);
    expect(screen.getByText('nobody')).toBeInTheDocument();
    expect(screen.queryByText('elsewhere')).not.toBeInTheDocument();
  });

  it('renders every contribution to the slot, in order, with the owner props', async () => {
    await renderSlot([contribute(GREETING, Hello), contribute(OTHER, () => <p>elsewhere</p>), contribute(GREETING, Bye)]);
    expect(screen.getAllByText(/Ada/).map((el) => el.textContent)).toEqual(['Hello Ada', 'Bye Ada']);
    expect(screen.queryByText('nobody')).not.toBeInTheDocument();
  });

  it('skips a contribution whose rule excludes the principal', async () => {
    await renderSlot([contribute(GREETING, Hello, { when: (p) => p?.role === 'admin' })]);
    expect(screen.getByText('nobody')).toBeInTheDocument();
  });

  it('shows the pending content while a lazy contribution loads', async () => {
    const Lazy = lazy(async () => ({ default: Hello }));
    await renderSlot([contribute(GREETING, Lazy)]);
    expect(screen.getByText('loading')).toBeInTheDocument();
    expect(await screen.findByText('Hello Ada')).toBeInTheDocument();
    expect(screen.queryByText('loading')).not.toBeInTheDocument();
  });

  it('refuses, at compile time, a contribution that does not take the slot props', () => {
    const NeedsCount = ({ count }: { count: number }) => <p>{count}</p>;
    // @ts-expect-error the greeting slot passes `name`, not `count`
    const wrong = contribute(GREETING, NeedsCount);
    expect(wrong.slot).toBe(GREETING);
  });

  it('keeps a contribution mounted when an earlier one stops applying', async () => {
    const mounts = vi.fn();
    const Counted = ({ name }: { name: string }) => {
      useEffect(() => mounts(), []);
      return <p>Counted {name}</p>;
    };
    let on = true;
    const list = () => [contribute(GREETING, Hello, { when: () => on }), contribute(GREETING, Counted)];
    const session = await signedInSession(fakeApi(() => ({})).api);
    const tree = (contributions: ReturnType<typeof list>) => (
      <SessionProvider session={session}>
        <ExtensionsProvider contributions={contributions}>
          <SlotOutlet slot={GREETING} props={{ name: 'Ada' }} />
        </ExtensionsProvider>
      </SessionProvider>
    );
    const { rerender } = render(tree(list()));
    expect(screen.getByText('Hello Ada')).toBeInTheDocument();
    on = false;
    rerender(tree(list()));
    expect(screen.queryByText('Hello Ada')).not.toBeInTheDocument();
    expect(screen.getByText('Counted Ada')).toBeInTheDocument();
    expect(mounts).toHaveBeenCalledTimes(1);
  });

  it('contains a contribution that crashes: the others still render', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    await renderSlot([contribute(GREETING, Broken), contribute(GREETING, Hello)]);
    expect(screen.getByText('Hello Ada')).toBeInTheDocument();
    expect(error).toHaveBeenCalled();
  });
});
