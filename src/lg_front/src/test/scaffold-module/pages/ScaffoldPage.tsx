import { PageHeader } from '../../../components/ui';
import { useThingCount } from '../api/hooks';

/** The scaffold module's one page. */
export default function ScaffoldPage() {
  const count = useThingCount();
  return (
    <>
      <PageHeader title="Scaffold things" description="The one page of the scaffold module." />
      <p className="text-sm text-body">{count === undefined ? 'Nothing waits.' : `${count} waiting.`}</p>
    </>
  );
}
