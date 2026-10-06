/**
 * Writes wrangler.production.jsonc: wrangler.jsonc with the production D1
 * database ID from D1_DATABASE_ID (shell, .env or build variable), so the ID
 * never has to be committed. See scripts/lib/production-config.ts.
 *
 *   npm run config:production
 */
import { productionConfig } from './lib/production-config';

console.log(productionConfig());
