import type { ElementType, ReactNode } from 'react';

/** Text for screen readers only (the `sr-only` clip pattern), e.g. the meaning of a count. */
export function VisuallyHidden({ children, as: Tag = 'span', id }: { children: ReactNode; as?: ElementType; id?: string }) {
  return (
    <Tag className="sr-only" id={id}>
      {children}
    </Tag>
  );
}
