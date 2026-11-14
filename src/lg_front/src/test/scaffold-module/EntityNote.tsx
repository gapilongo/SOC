/** The scaffold module's contribution to the SOC's `alert.entity` slot: a note next to each host. */
export default function EntityNote({ kind, value }: { kind: string; value: string }) {
  if (kind !== 'hosts') return null;
  return <span className="text-xs text-secondary">Scaffold note for {value}</span>;
}
