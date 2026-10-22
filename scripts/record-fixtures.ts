/**
 * Records small, real samples from every upstream source into test/fixtures/.
 * Tests use only these files and never hit the network.
 *
 *   npm run record-fixtures
 *
 * Set GITHUB_TOKEN to avoid the 60/h unauthenticated GitHub limit.
 * Re-run when an upstream format changes, then update the tests' expectations.
 *
 *   npm run record-fixtures -- --exploits   # only the exploit-availability ones
 */
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { strFromU8, unzipSync } from 'fflate';
import { GITHUB_API_VERSION, USER_AGENT } from '../src/config';
import { cveRecordUrl, RELEASES_URL } from '../src/ingest/sources/cve';
import { advisoriesUrl } from '../src/ingest/sources/ghsa';
import { KEV_URL } from '../src/ingest/sources/kev';
import { EPSS_URL } from '../src/ingest/sources/epss';
import { METASPLOIT_URL } from '../src/ingest/metasploit';
import { NUCLEI_URL } from '../src/ingest/nuclei';
import { REPORT_SOURCES } from '../src/ingest/reporters';
import { cveIdsIn, parseFeed } from '../src/ingest/reports';

const OUT = path.join(import.meta.dirname, '..', 'test', 'fixtures');

/** Records with references tagged "exploit": public exploit code. */
const EXPLOIT_CVES = [
  'CVE-2025-0168', // in the CNA's references
  'CVE-2025-0167', // only in the CISA-ADP container's
];

/** Metasploit modules kept: an exploit module naming several CVEs, an auxiliary one, and others. */
const METASPLOIT_MODULES = [
  'exploit_windows/smb/ms17_010_eternalblue', // exploit, six CVEs
  'auxiliary_scanner/smb/smb_ms17_010', // auxiliary, the same CVEs: the exploit module wins
  'auxiliary_scanner/http/log4shell_scanner', // auxiliary only
  'payload_windows/x64/meterpreter/reverse_tcp', // no CVEs
  'post_multi/recon/local_exploit_suggester', // post: left out
];

/** Records chosen for the shapes they exercise. */
const NAMED_CVES = [
  'CVE-2024-34393', // npm package via collectionURL, CVSS 3.1
  'CVE-2026-104910', // CPE, CVSS 4.0, CNA SSVC
  'CVE-2022-48816', // Linux kernel: git ranges, many branches, CISA ADP SSVC
  'CVE-2026-109618', // PHP: one fix per release branch, CVSS 4.0, CISA ADP SSVC
  // Rejected, for where a rejection points (cve_index.replaced_by):
  'CVE-2024-0228', // duplicate of one CVE
  'CVE-2023-0884', // reservation duplicate, ConsultIDs form
  'CVE-2002-0192', // ConsultIDs naming two
  'CVE-2025-0020', // not a vulnerability: points nowhere
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

/**
 * Metasploit's module index and Nuclei's cves.json, cut down to a few real
 * entries, with each file's ETag; and the CVE records with exploit references.
 */
async function recordExploits(): Promise<void> {
  const msf = await get(METASPLOIT_URL);
  const modules = (await msf.json()) as Record<string, unknown>;
  const kept = Object.fromEntries(METASPLOIT_MODULES.filter((k) => k in modules).map((k) => [k, modules[k]]));
  const missing = METASPLOIT_MODULES.filter((k) => !(k in modules));
  if (missing.length > 0) console.warn(`not in the Metasploit index any more: ${missing.join(', ')}`);
  await write('exploits/metasploit.json', { etag: msf.headers.get('etag'), body: kept });

  const nuclei = await get(NUCLEI_URL);
  const lines = (await nuclei.text()).split('\n').filter((l) => /"ID":"(CVE-2021-44228|CVE-2017-0144|CVE-2024-3400|CVE-2023-4966|CVE-2000-0114)"/.test(l));
  await write('exploits/nuclei.json', { etag: nuclei.headers.get('etag'), lines });

  for (const id of EXPLOIT_CVES) await write(`cve/records/${id}.json`, await (await get(cveRecordUrl(id))).json());
}

/** Items kept from each trusted source's feed: enough for PHP2Shell's write-ups on 2026-10-21. */
const REPORT_ITEMS = 6;
/** Pages kept per source that reads them (CERT-EU's JSON, NCSC UK's news pages). */
const REPORT_PAGES = 2;

/**
 * Each trusted source's RSS feed cut to its newest items, as served, and the
 * pages of the first items whose feed entry names no CVE.
 */
async function recordReports(): Promise<void> {
  const feeds: Record<string, { etag: string | null; body: string }> = {};
  const pages: Record<string, string> = {};
  for (const src of REPORT_SOURCES) {
    const res = await get(src.feed);
    const xml = await res.text();
    const head = xml.slice(0, Math.max(0, xml.indexOf('<item')));
    const items = parseFeed(xml).length;
    let at = head.length;
    for (let i = 0; i < Math.min(REPORT_ITEMS, items); i++) at = xml.indexOf('</item>', at) + '</item>'.length;
    feeds[src.id] = { etag: res.headers.get('etag'), body: `${xml.slice(0, at)}
</channel>
</rss>
` };
    if (!src.page) continue;
    let kept = 0;
    for (const item of parseFeed(xml.slice(0, at))) {
      if (kept >= REPORT_PAGES || !item.link || cveIdsIn(`${item.title}
${item.text}`).length > 0 || !src.page.when.test(item.title)) continue;
      const url = src.page.url(item.link);
      pages[url] = await (await get(url)).text();
      kept++;
    }
  }
  await write('reports/feeds.json', feeds);
  await write('reports/pages.json', pages);
}

if (process.argv.includes('--exploits')) {
  await recordExploits();
  process.exit(0);
}
if (process.argv.includes('--reports')) {
  await recordReports();
  process.exit(0);
}

await recordExploits();
await recordReports();
const cveIds = await recordCve();
const ghsaCves = await recordGhsa();
const kevIds = await recordKev();
await recordEpss([...new Set([...NAMED_CVES, ...cveIds, ...ghsaCves, ...kevIds])]);
