import { beforeEach, describe, expect, it } from 'vitest';
import { applyPatches, type ApplyOptions } from '../src/ingest/apply';
import { maintenanceStatements } from '../src/ingest/maintenance';
import { parseCveRecord } from '../src/ingest/sources/cve-record';
import { parseAdvisory } from '../src/ingest/sources/ghsa';
import type { AffectedInput, VulnPatch } from '../src/ingest/types';
import { cveRecords, ghsaPage } from './helpers/fixtures';
import { resetDb, rows, store } from './helpers/db';

const NOW = new Date('2026-10-04T18:00:00Z');
const opts: ApplyOptions = { now: NOW, windowStart: '2026-07-06T18:00:00.000Z', epssEvents: true };
const advisories = ghsaPage.advisories as Record<string, unknown>[];
const advisory = (id: string) => advisories.find((a) => a.ghsa_id === id)!;

const pkg = (name: string, fixedVersion: string | null, range = '< 2.0.0'): AffectedInput => ({
  kind: 'package',
  ecosystem: 'npm',
  packageName: name,
  label: name,
  ranges: [{ range }],
  fixedVersion,
});

function ghsa(id: string, over: Partial<VulnPatch> = {}): VulnPatch {
  return {
    source: 'ghsa',
    id,
    aliases: [],
    fields: { title: `${id} title`, publishedAt: '2026-10-01T00:00:00.000Z', modifiedAt: '2026-10-01T00:00:00.000Z' },
    affected: [pkg('left-pad', null)],
    ...over,
  };
}

beforeEach(resetDb);

describe('applyPatches', () => {
  it('stores records, affected rows, aliases, events and catalog entries', async () => {
    const stats = await applyPatches(store(), [parseAdvisory(advisory('GHSA-wp3j-xq48-xpjw'))!], opts);
    // CVE-2025-9566 was published long before the window: skipped.
    expect(stats).toMatchObject({ received: 1, written: 0, skipped: 1 });

    const recent = await applyPatches(store(), [parseCveRecord(cveRecords['CVE-2026-104910'])!], opts);
    expect(recent).toMatchObject({ written: 1, events: 1, inserted: ['CVE-2026-104910'] });
    expect(await rows('SELECT vuln_id, kind, vendor, product, fixed_version FROM affected')).toEqual([
      { vuln_id: 'CVE-2026-104910', kind: 'product', vendor: 'misp', product: 'misp', fixed_version: '2.5.48' },
    ]);
    expect(await rows('SELECT vuln_id, type, occurred_at FROM events')).toEqual([
      { vuln_id: 'CVE-2026-104910', type: 'published', occurred_at: '2026-10-02T16:01:32.781Z' },
    ]);
    expect(await rows('SELECT kind, key, label FROM catalog')).toEqual([{ kind: 'product', key: 'misp/misp', label: 'MISP' }]);
  });

  it('writes nothing when the same data arrives again', async () => {
    const patch = parseCveRecord(cveRecords['CVE-2026-104910'])!;
    await applyPatches(store(), [patch], opts);
    const again = await applyPatches(store(), [patch], opts);
    expect(again).toMatchObject({ written: 0, events: 0, inserted: [] });
    expect(await rows('SELECT COUNT(*) AS n FROM events')).toEqual([{ n: 1 }]);
  });

  it('merges a GHSA and a CVE describing the same issue into one record', async () => {
    const cve: VulnPatch = { source: 'cve', id: 'CVE-2026-61834', aliases: [], fields: { title: 'From CVE', publishedAt: '2026-09-20T00:00:00.000Z' } };
    await applyPatches(store(), [cve], opts);
    await applyPatches(store(), [parseAdvisory(advisory('GHSA-2mhw-wcx5-v3xj'))!], opts);

    const vulns = await rows<{ id: string; title: string; aliases: string; source_flags: number }>('SELECT id, title, aliases, source_flags FROM vulns');
    expect(vulns).toEqual([{ id: 'CVE-2026-61834', title: 'From CVE', aliases: '["GHSA-2mhw-wcx5-v3xj"]', source_flags: 3 }]);
    expect(await rows('SELECT alias, vuln_id FROM aliases')).toEqual([{ alias: 'GHSA-2mhw-wcx5-v3xj', vuln_id: 'CVE-2026-61834' }]);
    expect(await rows('SELECT source, package_name FROM affected')).toEqual([{ source: 'ghsa', package_name: 'scim-patch' }]);
  });

  it('re-keys a GHSA-only record when the advisory gains a CVE ID', async () => {
    await applyPatches(store(), [ghsa('GHSA-456v-xq2p-r4cj')], opts);
    expect(await rows('SELECT id FROM vulns')).toEqual([{ id: 'GHSA-456v-xq2p-r4cj' }]);

    const withCve = ghsa('CVE-2026-99999', { aliases: ['GHSA-456v-xq2p-r4cj'] });
    await applyPatches(store(), [withCve], opts);

    expect(await rows('SELECT id, aliases FROM vulns')).toEqual([{ id: 'CVE-2026-99999', aliases: '["GHSA-456v-xq2p-r4cj"]' }]);
    expect(await rows('SELECT DISTINCT vuln_id FROM affected')).toEqual([{ vuln_id: 'CVE-2026-99999' }]);
    expect(await rows('SELECT vuln_id, type FROM events')).toEqual([{ vuln_id: 'CVE-2026-99999', type: 'published' }]);
    expect(await rows('SELECT alias, vuln_id FROM aliases')).toEqual([{ alias: 'GHSA-456v-xq2p-r4cj', vuln_id: 'CVE-2026-99999' }]);
  });

  it('applies a later GHSA-only update to the CVE-keyed record through its alias', async () => {
    await applyPatches(store(), [ghsa('CVE-2026-99999', { aliases: ['GHSA-456v-xq2p-r4cj'] })], opts);
    // An advisory that briefly lost its CVE ID still lands on the same record.
    await applyPatches(store(), [ghsa('GHSA-456v-xq2p-r4cj', { affected: [pkg('left-pad', '2.0.0')] })], opts);
    expect(await rows('SELECT id FROM vulns')).toEqual([{ id: 'CVE-2026-99999' }]);
    expect(await rows('SELECT fixed_version FROM affected')).toEqual([{ fixed_version: '2.0.0' }]);
  });

  it('records fix_released when a package gets its first patched version', async () => {
    await applyPatches(store(), [ghsa('GHSA-456v-xq2p-r4cj')], opts);
    const fixed = ghsa('GHSA-456v-xq2p-r4cj', {
      fields: { modifiedAt: '2026-10-04T10:00:00.000Z' },
      affected: [pkg('left-pad', '2.0.0')],
    });
    const stats = await applyPatches(store(), [fixed], opts);
    expect(stats.events).toBe(1);
    expect(await rows("SELECT type, occurred_at, dedupe_key, json_extract(detail, '$.fixedVersion') AS v FROM events WHERE type = 'fix_released'")).toEqual([
      { type: 'fix_released', occurred_at: '2026-10-04T10:00:00.000Z', dedupe_key: 'pkg:npm:left-pad@2.0.0', v: '2.0.0' },
    ]);
    expect(await rows('SELECT last_event_at FROM vulns')).toEqual([{ last_event_at: '2026-10-04T10:00:00.000Z' }]);
  });

  it('replaces only the patching source’s affected rows', async () => {
    const kev: VulnPatch = {
      source: 'kev',
      id: 'CVE-2026-99999',
      aliases: [],
      fields: { kevAddedAt: '2026-10-02T00:00:00.000Z' },
      affected: [{ kind: 'product', vendor: 'acme', product: 'widget', ranges: [] }],
    };
    await applyPatches(store(), [ghsa('CVE-2026-99999'), kev], opts);
    await applyPatches(store(), [ghsa('CVE-2026-99999', { affected: [pkg('right-pad', null)] })], opts);
    expect(await rows('SELECT source, COALESCE(package_name, product) AS name FROM affected ORDER BY source')).toEqual([
      { source: 'ghsa', name: 'right-pad' },
      { source: 'kev', name: 'widget' },
    ]);
  });

  it('deletes rejected CVEs and withdrawn GHSA-only advisories', async () => {
    await applyPatches(store(), [ghsa('GHSA-456v-xq2p-r4cj'), ghsa('CVE-2026-104886')], opts);
    const stats = await applyPatches(
      store(),
      [
        parseCveRecord(cveRecords['CVE-2026-104886'])!,
        { source: 'ghsa', id: 'GHSA-456v-xq2p-r4cj', aliases: [], fields: {}, withdrawn: true },
      ],
      opts,
    );
    expect(stats.deleted).toBe(2);
    for (const t of ['vulns', 'affected', 'events', 'aliases']) expect(await rows(`SELECT * FROM ${t}`)).toEqual([]);
  });

  it('drops only the package rows when an advisory on a CVE record is withdrawn', async () => {
    await applyPatches(store(), [ghsa('CVE-2026-99999', { aliases: ['GHSA-456v-xq2p-r4cj'] })], opts);
    await applyPatches(store(), [{ source: 'ghsa', id: 'CVE-2026-99999', aliases: [], fields: {}, withdrawn: true }], opts);
    expect(await rows('SELECT id FROM vulns')).toEqual([{ id: 'CVE-2026-99999' }]);
    expect(await rows('SELECT * FROM affected')).toEqual([]);
  });

  it('writes the extra statements in the same batch', async () => {
    await applyPatches(store(), [], {
      ...opts,
      extraStatements: [{ sql: "INSERT INTO meta (key, value, updated_at) VALUES ('k', '1', 'now')", params: [] }],
    });
    expect(await rows('SELECT key FROM meta')).toEqual([{ key: 'k' }]);
  });

  it('handles pages larger than one JSON chunk', async () => {
    const patches = Array.from({ length: 600 }, (_, i) =>
      ghsa(`CVE-2026-${200000 + i}`, { fields: { title: 'x'.repeat(400), publishedAt: '2026-10-01T00:00:00.000Z' } }),
    );
    const stats = await applyPatches(store(), patches, opts);
    expect(stats.written).toBe(600);
    expect(await rows('SELECT COUNT(*) AS n FROM vulns')).toEqual([{ n: 600 }]);
    expect(await rows('SELECT COUNT(*) AS n FROM affected')).toEqual([{ n: 600 }]);
  });
});

describe('maintenance', () => {
  async function run(now: Date): Promise<void> {
    const s = store();
    await s.batch(maintenanceStatements(now));
  }

  it('prunes by activity: old records go, an old CVE with a recent KEV event stays', async () => {
    const old: VulnPatch = { source: 'cve', id: 'CVE-2026-0001', aliases: [], fields: { publishedAt: '2026-08-01T00:00:00.000Z' }, affected: [pkg('a', null)] };
    const kevd: VulnPatch = { source: 'kev', id: 'CVE-2020-29583', aliases: [], fields: { kevAddedAt: '2026-10-02T00:00:00.000Z' } };
    const fresh: VulnPatch = { source: 'cve', id: 'CVE-2026-0002', aliases: [], fields: { publishedAt: '2026-10-01T00:00:00.000Z' } };
    await applyPatches(store(), [old, kevd, fresh], opts);

    // Dec 26: the Aug 1 publication is 147 days old; the Oct 1 publication and
    // the Oct 2 KEV addition are both inside 90 days.
    await run(new Date('2026-12-26T00:00:00Z'));
    expect((await rows<{ id: string }>('SELECT id FROM vulns ORDER BY id')).map((r) => r.id)).toEqual(['CVE-2020-29583', 'CVE-2026-0002']);
    expect(await rows("SELECT * FROM affected WHERE vuln_id = 'CVE-2026-0001'")).toEqual([]);
    expect(await rows("SELECT * FROM events WHERE vuln_id = 'CVE-2026-0001'")).toEqual([]);
  });

  it('keeps a record published exactly at the window start', async () => {
    const p: VulnPatch = { source: 'cve', id: 'CVE-2026-0003', aliases: [], fields: { publishedAt: '2026-10-01T00:00:00.000Z' } };
    await applyPatches(store(), [p], opts);
    await run(new Date('2026-12-30T00:00:00Z')); // exactly 90 days later
    expect(await rows('SELECT id FROM vulns')).toEqual([{ id: 'CVE-2026-0003' }]);
    await run(new Date('2026-12-30T00:00:00.001Z'));
    expect(await rows('SELECT id FROM vulns')).toEqual([]);
  });

  it('recounts the catalog and keeps entries at zero', async () => {
    await applyPatches(store(), [ghsa('CVE-2026-1001'), ghsa('CVE-2026-1002')], opts);
    await run(NOW);
    expect(await rows('SELECT key, count FROM catalog')).toEqual([{ key: 'npm:left-pad', count: 2 }]);
    await run(new Date('2027-02-01T00:00:00Z'));
    expect(await rows('SELECT key, count FROM catalog')).toEqual([{ key: 'npm:left-pad', count: 0 }]);
  });
});
