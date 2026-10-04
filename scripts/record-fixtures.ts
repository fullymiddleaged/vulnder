/**
 * Records small, real samples from every upstream source into test/fixtures/.
 * Tests use only these files and never hit the network.
 *
 *   npm run record-fixtures
 *
 * Set GITHUB_TOKEN to avoid the 60/h unauthenticated GitHub limit.
 * Re-run when an upstream format changes, then update the tests' expectations.
 */
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { strFromU8, unzipSync } from 'fflate';
import { GITHUB_API_VERSION, USER_AGENT } from '../src/config';
import { cveRecordUrl, RELEASES_URL } from '../src/ingest/sources/cve';
import { advisoriesUrl } from '../src/ingest/sources/ghsa';
import { KEV_URL } from '../src/ingest/sources/kev';
import { EPSS_URL } from '../src/ingest/sources/epss';

const OUT = path.join(import.meta.dirname, '..', 'test', 'fixtures');

/** Records chosen for the shapes they exercise. */
const NAMED_CVES = [
  'CVE-2024-34393', // npm package via collectionURL, CVSS 3.1
  'CVE-2026-104910', // CPE, CVSS 4.0, CNA SSVC
  'CVE-2022-48816', // Linux kernel: git ranges, many branches, CISA ADP SSVC
];

const gh: Record<string, string> = {
  'User-Agent': USER_AGENT,
  Accept: 'application/vnd.github+json',
  'X-GitHub-Api-Version': GITHUB_API_VERSION,
};
if (process.env.GITHUB_TOKEN) gh.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;

async function get(url: string, headers: Record<string, string> = { 'User-Agent': USER_AGENT }): Promise<Response> {
  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res;
}

async function write(rel: string, data: unknown): Promise<void> {
  const file = path.join(OUT, rel);
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, `${JSON.stringify(data, null, 2)}\n`);
  console.log(`wrote ${path.relative(process.cwd(), file)}`);
}

type Release = { tag_name: string; published_at: string; assets: { name: string; size: number; browser_download_url: string }[] };

async function recordCve(): Promise<string[]> {
  const releases = (await (await get(RELEASES_URL, gh)).json()) as Release[];
  const trimmed = releases.slice(0, 40).map((r) => ({
    tag_name: r.tag_name,
    published_at: r.published_at,
    assets: r.assets
      .filter((a) => a.name.includes('_delta_CVEs_at_'))
      .map((a) => ({ name: a.name, size: a.size, browser_download_url: a.browser_download_url })),
  }));
  await write('cve/releases.json', trimmed);

  const ids: string[] = [];
  for (const id of NAMED_CVES) {
    const record = await (await get(cveRecordUrl(id))).json();
    await write(`cve/records/${id}.json`, record);
    ids.push(id);
  }

  // A rejected record and a few ordinary ones from recent end-of-day zips.
  let rejected = false;
  let ordinary = 0;
  for (const r of releases.filter((r) => /_at_end_of_day$/.test(r.tag_name)).slice(0, 4)) {
    const asset = r.assets.find((a) => a.name.endsWith('_delta_CVEs_at_end_of_day.zip'));
    if (!asset) continue;
    const files = unzipSync(new Uint8Array(await (await get(asset.browser_download_url)).arrayBuffer()));
    for (const data of Object.values(files)) {
      const record = JSON.parse(strFromU8(data)) as { cveMetadata: { cveId: string; state: string; datePublished?: string } };
      const id = record.cveMetadata.cveId;
      if (ids.includes(id)) continue;
      if (!rejected && record.cveMetadata.state === 'REJECTED') {
        rejected = true;
        await write(`cve/records/${id}.json`, record);
        ids.push(id);
      } else if (ordinary < 3 && record.cveMetadata.state === 'PUBLISHED' && record.cveMetadata.datePublished?.startsWith('2026')) {
        ordinary++;
        await write(`cve/records/${id}.json`, record);
        ids.push(id);
      }
      if (rejected && ordinary >= 3) break;
    }
    if (rejected && ordinary >= 3) break;
  }
  if (!rejected) console.warn('no REJECTED record found in recent zips; the rejected-record test keeps its previous fixture');
  return ids.filter((id) => !NAMED_CVES.includes(id));
}

async function recordGhsa(): Promise<string[]> {
  const since = new Date(Date.now() - 7 * 86_400_000).toISOString();
  const res = await get(advisoriesUrl(since).replace('per_page=100', 'per_page=60'), gh);
  const all = (await res.json()) as Record<string, unknown>[];
  const withCve = all.filter((a) => a.cve_id).slice(0, 3);
  const withoutCve = all.filter((a) => !a.cve_id).slice(0, 2);
  const picked = [...withCve, ...withoutCve].map((a) => {
    const { credits: _credits, ...rest } = a;
    return { ...rest, description: String(rest.description ?? '').slice(0, 600) };
  });
  await write('ghsa/page.json', { link: res.headers.get('link'), advisories: picked });
  return withCve.map((a) => String(a.cve_id));
}

async function recordKev(): Promise<string[]> {
  const res = await get(KEV_URL);
  const feed = (await res.json()) as { vulnerabilities: Record<string, string>[] } & Record<string, unknown>;
  const v = feed.vulnerabilities;
  const picked = [
    ...v.slice(0, 3),
    v.find((e) => e.product?.startsWith('Multiple')),
    v.find((e) => e.knownRansomwareCampaignUse === 'Known'),
    v[v.length - 1],
  ].filter((e, i, arr): e is Record<string, string> => !!e && arr.indexOf(e) === i);
  await write('kev/feed.json', {
    headers: { etag: res.headers.get('etag'), 'last-modified': res.headers.get('last-modified') },
    body: { ...feed, count: picked.length, vulnerabilities: picked },
  });
  return picked.map((e) => e.cveID!);
}

async function recordEpss(ids: string[]): Promise<void> {
  const latest = await (await get(`${EPSS_URL}?limit=1`)).json();
  await write('epss/latest.json', latest);
  const date = (latest as { data: { date: string }[] }).data[0]!.date;
  const url = `${EPSS_URL}?${new URLSearchParams({ cve: ids.join(','), date, limit: String(ids.length + 10) })}`;
  await write('epss/scores.json', { request: { cve: ids, date }, body: await (await get(url)).json() });
}

const cveIds = await recordCve();
const ghsaCves = await recordGhsa();
const kevIds = await recordKev();
await recordEpss([...new Set([...NAMED_CVES, ...cveIds, ...ghsaCves, ...kevIds])]);
