import { Activity } from 'lucide-react';

import { PRODUCT_NAME, type Brand } from '../../config';

/** Two letters for a brand without a logo: the initials of its first two words ("Brightwater SOC" -> "BS"). */
export function brandInitials(name: string): string {
  const words = name.split(/[\s._-]+/).filter(Boolean);
  const letters = words.length >= 2 ? words[0][0] + words[1][0] : name.slice(0, 2);
  return letters.toUpperCase();
}

/**
 * The brand's mark, 24 px: its logo when it has one, the product's own mark
 * for the product, otherwise two letters on the accent. Decorative: the name
 * stands next to it.
 */
export function BrandMark({ brand }: { brand: Brand }) {
  if (brand.logoUrl) return <img src={brand.logoUrl} alt="" className="h-6 w-6 flex-none object-contain" />;
  return (
    <span aria-hidden="true" className="grid h-6 w-6 flex-none place-items-center rounded-tag bg-accent text-2xs font-bold text-on-accent">
      {brand.name === PRODUCT_NAME ? <Activity className="h-3.5 w-3.5" strokeWidth={2.25} /> : brandInitials(brand.name)}
    </span>
  );
}
