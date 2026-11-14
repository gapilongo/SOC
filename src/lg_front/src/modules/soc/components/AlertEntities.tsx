/**
 * An alert's entities by kind, in the alert panel (`stacked`) and on the
 * decision page (`columns`): one shared `EntityList`, one set of labels, and
 * the `alert.entity` extension point next to every value, so another
 * service's cross-link shows in both places.
 */

import { SlotOutlet } from '../../../components/Slot';
import { EntityList, type EntityListLayout } from '../../../components/ui';
import { humanize } from '../../../lib/format';
import { ALERT_ENTITY } from '../slots';

const ENTITY_LABELS: Record<string, string> = {
  hosts: 'Hosts',
  users: 'Users',
  ips: 'IP addresses',
  domains: 'Domains',
  urls: 'URLs',
  hashes: 'File hashes',
  processes: 'Processes',
  command_lines: 'Command lines',
  emails: 'Email addresses',
};

/** A kind of `normalized.entities` in words. */
export function entityLabel(kind: string): string {
  return ENTITY_LABELS[kind] ?? humanize(kind);
}

const afterEntity = (kind: string, value: string) => <SlotOutlet slot={ALERT_ENTITY} props={{ kind, value }} />;

/** `entities`: `[kind, values]` pairs, non-empty kinds only. */
export function AlertEntities({ entities, layout }: { entities: ReadonlyArray<readonly [string, readonly string[]]>; layout: EntityListLayout }) {
  return <EntityList layout={layout} groups={entities.map(([kind, values]) => ({ kind, label: entityLabel(kind), values }))} after={afterEntity} />;
}
