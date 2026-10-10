/**
 * Lists where the curated name tables have fallen behind the catalog (see
 * scripts/lib/name-drift.ts). Reads the catalog's products once, about 12,000
 * rows; it changes nothing.
 *
 *   npm run check:names               # local D1
 *   npm run check:names -- --remote   # production
 */
import { nameDrift, type CatalogProduct } from './lib/name-drift';
import { parseArgs, parseTarget } from './lib/args';
import { productionConfig } from './lib/production-config';
import { WranglerStore } from './lib/wrangler-store';

const { values } = parseArgs({ options: { local: { type: 'boolean' }, remote: { type: 'boolean' } } });
const target = parseTarget(values);
const store = new WranglerStore({ target, config: target === 'remote' ? productionConfig() : undefined });

const rows = await store.all<CatalogProduct>("SELECT key, vendor, product, count FROM catalog WHERE kind = 'product'");
const drift = nameDrift(rows);
console.log(drift.length === 0 ? `No drift across ${rows.length} products.` : drift.join('\n'));
