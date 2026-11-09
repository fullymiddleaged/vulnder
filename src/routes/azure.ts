import { Hono } from 'hono';
import template from '../../integrations/azure/azuredeploy.json';
import form from '../../integrations/azure/createUiDefinition.json';
import { isCveItem, type StackItem } from '../stack/format';
import { isEdge } from '../stack/teams';
import type { AppEnv } from '../types';
import { baseUrl, DEFAULT_DAYS, stackRequest } from './feeds';

/**
 * The Azure template and its portal form, for the Deploy to Azure button on
 * the results page. With ?s= (and ?days=), the form comes with that stack in
 * it, named in words, so nobody types the stack format. The Azure portal
 * fetches both from the browser, so they need CORS. Nothing here logs the
 * stack; query strings are redacted from logs (wrangler.jsonc).
 */

const HEADERS = { 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'public, max-age=300' };

type Element = { name: string; [key: string]: unknown };
type Form = typeof form;

/** One stack item as the results page names it: `fortinet/fortios 7.4.3 (edge)`. */
export function itemWords(item: StackItem): string {
  if (isCveItem(item)) return item.id;
  const name = item.kind === 'product' ? `${item.vendor}/${item.product}` : `${item.ecosystem} ${item.name}`;
  const notes = [item.close ? 'close match' : null, isEdge(item) ? 'edge' : null].filter((n) => n !== null);
  return `${name}${item.version ? ` ${item.version}` : ''}${notes.length > 0 ? ` (${notes.join(', ')})` : ''}`;
}

/** The portal form, pointing at this deployment, with the stack in it when there is one. */
export function formFor(base: string, stack?: { items: StackItem[]; canonical: string; days: number }): Form {
  const ui = structuredClone(form);
  const settings = ui.parameters.steps[0]!.elements as Element[];
  const url = settings.find((e) => e.name === 'vulnderUrl')!;
  url.defaultValue = base;
  if (!stack) return ui;
  const days = settings.find((e) => e.name === 'days')!;
  days.defaultValue = stack.days;
  // The stack box gives way to the stack in words; the template gets the stack itself.
  const basics = ui.parameters.basics as Element[];
  const at = basics.findIndex((e) => e.name === 'stack');
  const shown = stack.items.slice(0, 50).map(itemWords).join(', ');
  const more = stack.items.length > 50 ? `, and ${stack.items.length - 50} more` : '';
  basics.splice(at, 1, {
    name: 'stackSummary',
    type: 'Microsoft.Common.InfoBox',
    options: {
      icon: 'Info',
      text: `Your stack from ${new URL(base).host}: ${shown}${more}. In modes Defender and Intune, it's ranked alongside what they find. To change it, edit it on the results page and deploy from there again.`,
    },
  });
  // A literal output; a stack never starts with '[', which would make it an expression.
  (ui.parameters.outputs as Record<string, string>).stack = stack.canonical;
  return ui;
}

export const azure = new Hono<AppEnv>()
  .get('/azuredeploy.json', (c) => c.json(template, 200, HEADERS))
  .get('/createUiDefinition.json', (c) => {
    const base = baseUrl(c.env);
    const s = c.req.query('s');
    if (s === undefined) return c.json(formFor(base), 200, HEADERS);
    const daysParam = c.req.query('days');
    const req = stackRequest(s, daysParam === undefined ? DEFAULT_DAYS : Number(daysParam));
    if ('error' in req) return c.json(req, 400, HEADERS);
    return c.json(formFor(base, req), 200, HEADERS);
  });
