/**
 * Fails if integrations/azure/azuredeploy.json, which the Deploy to Azure
 * button and releases use, isn't what main.bicep builds to. Needs the Bicep
 * CLI on PATH. Rebuild with `npm run build:azure`.
 *
 *   npm run check:azure
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { sameTemplate } from './lib/release';

const committed = readFileSync('integrations/azure/azuredeploy.json', 'utf8');
const built = execFileSync('bicep', ['build', 'integrations/azure/main.bicep', '--stdout'], { encoding: 'utf8' });
if (!sameTemplate(committed, built)) {
  console.error('integrations/azure/azuredeploy.json is out of date with main.bicep. Run `npm run build:azure` and commit the result.');
  process.exit(1);
}
console.log('azuredeploy.json matches main.bicep.');
