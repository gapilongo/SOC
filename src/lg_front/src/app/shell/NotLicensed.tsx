import { useAuth } from '../../auth/AuthContext';
import type { ModuleManifest } from '../../core/module';

/**
 * The page of a service this installation's licence does not include.
 *
 * A platform admin reaches it from the locked group in the rail: it says in
 * words that the service is not licensed, that nothing is collected or
 * hidden, and what the service would add. Anyone else only gets here by
 * typing the address, and is told the page is not part of their console,
 * with nothing to buy.
 */
export function NotLicensed({ module }: { module: Pick<ModuleManifest, 'title' | 'offers'> }) {
  const { principal } = useAuth();
  if (!principal?.isPlatformAdmin) {
    return (
      <div className="py-16 text-center">
        <h1 className="text-lg font-semibold text-fg">This page is not part of your console</h1>
        <p className="mt-2 text-sm text-secondary">{module.title} is not enabled for your organisation. The rest of the console works as before.</p>
      </div>
    );
  }
  const offers = module.offers ?? [];
  return (
    <div className="grid max-w-[1100px] gap-x-8 gap-y-5 py-2 min-[861px]:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
      <div>
        <span className="rounded-[2px] border border-strong px-1.5 py-[3px] font-mono text-[10.5px] font-medium uppercase leading-none tracking-[0.05em] text-secondary">
          Not licensed
        </span>
        <h1 className="my-1.5 text-lg font-semibold leading-snug tracking-[-0.01em] text-fg">
          {module.title} is not part of this installation&apos;s licence.
        </h1>
        <p className="text-ctl text-body">
          Nothing is collected and nothing is hidden from you: the service is switched off and holds no data. The rest of the console works as before.
        </p>
      </div>
      {offers.length > 0 && (
        <div>
          <h2 className="eyebrow mb-1">What it would add</h2>
          <ul className="text-ctl text-body">
            {offers.map((line) => (
              <li key={line} className="relative py-1 pl-4 before:absolute before:left-0.5 before:top-3 before:h-px before:w-1.5 before:bg-control">
                {line}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
