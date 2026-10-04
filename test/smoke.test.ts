import { env } from 'cloudflare:workers';
import { expect, it } from 'vitest';

it('has the schema', async () => {
  const { results } = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all<{ name: string }>();
  expect(results.map((r) => r.name)).toEqual(expect.arrayContaining(['affected', 'aliases', 'catalog', 'events', 'meta', 'vulns']));
});
