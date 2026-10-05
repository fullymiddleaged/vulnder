import { parseManifest } from '../src/resolve/manifests';
import { parseStack, serializeStack, StackFormatError, type StackItem } from '../src/stack/format';
import { ApiError, getConfig, getFeed, getHealth, resolve, type AppConfig, type Chip, type Feed, type Result } from './api';
import { clear, h, safeHref } from './dom';
import { ago, describeChange, matchHeadline, ordinal, pct } from './format';

declare global {
  interface Window {
    turnstile?: {
      render(el: HTMLElement, opts: Record<string, unknown>): string;
      reset(id?: string): void;
    };
  }
}

const EXAMPLES = [
  { label: 'Web app', text: 'Next.js 14.2.3 on Vercel, Postgres 16, Redis, nginx' },
  { label: 'Python API', text: 'Django 4.2, Celery, RabbitMQ, PostgreSQL 15, running behind Apache httpd' },
  { label: 'Office network', text: 'Cisco IOS XE switches, FortiGate firewall, Microsoft Exchange, VMware vCenter' },
];
const MAX_TEXT = 2000;
const TIER_TITLE: Record<Result['tier'], string> = { exploited: 'Exploited', likely: 'Likely', backlog: 'Backlog' };
const TIER_NOTE: Record<Result['tier'], string> = {
  exploited: 'On the CISA Known Exploited Vulnerabilities list.',
  likely: 'EPSS of 10% or more: a predicted probability of exploitation in the next 30 days.',
  backlog: 'Matched your stack, with neither signal.',
};

const app = document.getElementById('app')!;
const status = document.getElementById('status')!;
let config: AppConfig | null = null;
let turnstileToken: string | null = null;
let turnstileWidget: string | undefined;

function say(message: string): void {
  status.textContent = message;
}

// ---------- Input ----------

function renderInput(prefill = ''): void {
  clear(app);
  const textarea = h('textarea', {
    id: 'stack-text',
    rows: 6,
    maxlength: 200_000,
    placeholder: 'For example: Next.js 14 on Vercel, Postgres 16, Redis, nginx, a couple of Cisco switches',
    'aria-describedby': 'stack-help',
  });
  textarea.value = prefill;
  const counter = h('span', { class: 'counter', 'aria-hidden': 'true' });
  const updateCounter = () => {
    const isManifest = !!parseManifest(textarea.value);
    counter.textContent = isManifest ? 'Manifest detected' : `${textarea.value.length} / ${MAX_TEXT}`;
    counter.classList.toggle('over', !isManifest && textarea.value.length > MAX_TEXT);
  };
  textarea.addEventListener('input', updateCounter);
  updateCounter();

  const fileInput = h('input', { type: 'file', id: 'file', class: 'visually-hidden', accept: '.json,.txt,.toml,.mod,.xml,.lock,Dockerfile,*' }) as HTMLInputElement;
  const drop = h(
    'div',
    { class: 'drop', id: 'drop' },
    h('p', {}, 'Drop a manifest here, or ', h('label', { for: 'file', class: 'link' }, 'choose a file'), '.'),
    h('p', { class: 'muted small' }, 'package.json, lockfiles, requirements.txt, pyproject.toml, go.mod, Cargo.toml, pom.xml, Gemfile.lock, composer.json, Dockerfile, CycloneDX or SPDX JSON. Files are read in your browser; only package names and versions are sent.'),
    fileInput,
  );
  const onFile = async (file: File) => {
    if (file.size > 5_000_000) return say('That file is larger than 5 MB.');
    const text = await file.text();
    const manifest = parseManifest(text, file.name);
    if (!manifest) return say(`${file.name} is not a manifest format Vulnder reads.`);
    say(`Read ${manifest.candidates.length} entries from ${file.name}.`);
    await submit({ candidates: manifest.candidates });
  };
  fileInput.addEventListener('change', () => fileInput.files?.[0] && onFile(fileInput.files[0]));
  drop.addEventListener('dragover', (e) => {
    e.preventDefault();
    drop.classList.add('over');
  });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (e) => {
    e.preventDefault();
    drop.classList.remove('over');
    const file = e.dataTransfer?.files?.[0];
    if (file) void onFile(file);
  });

  const turnstileBox = h('div', { class: 'turnstile' });
  const submitButton = h('button', { type: 'submit', class: 'primary' }, 'Find vulnerabilities');
  const form = h(
    'form',
    {
      class: 'card',
      onsubmit: (e: Event) => {
        e.preventDefault();
        const text = textarea.value.trim();
        if (!text) return say('Describe your stack or paste a manifest first.');
        const manifest = parseManifest(text);
        if (manifest) return void submit({ candidates: manifest.candidates });
        if (text.length > MAX_TEXT) return say(`Descriptions are limited to ${MAX_TEXT} characters. Paste a manifest file instead.`);
        void submit({ text });
      },
    },
    h('label', { for: 'stack-text', class: 'label' }, 'Describe your stack, or paste a manifest'),
    textarea,
    h('div', { class: 'row' }, h('p', { id: 'stack-help', class: 'muted small' }, 'Name what you run, with versions where you know them.'), counter),
    turnstileBox,
    submitButton,
  );

  const examples = h(
    'div',
    { class: 'examples' },
    h('span', { class: 'muted' }, 'Try an example:'),
    EXAMPLES.map((ex) =>
      h('button', { type: 'button', class: 'chip-button', onclick: () => ((textarea.value = ex.text), updateCounter(), textarea.focus()) }, ex.label),
    ),
  );

  app.append(form, examples, drop);
  mountTurnstile(turnstileBox);
}

function mountTurnstile(box: HTMLElement): void {
  if (!config) return;
  const tryRender = () => {
    if (!window.turnstile) return void setTimeout(tryRender, 200);
    turnstileWidget = window.turnstile.render(box, {
      sitekey: config!.turnstileSiteKey,
      callback: (token: string) => (turnstileToken = token),
      'expired-callback': () => (turnstileToken = null),
      'error-callback': () => (turnstileToken = null),
    });
  };
  tryRender();
}

async function submit(body: { text: string } | { candidates: import('../src/resolve/types').Candidate[] }): Promise<void> {
  if (!turnstileToken) return say('Please wait for the verification check to finish, then try again.');
  const token = turnstileToken;
  turnstileToken = null;
  window.turnstile?.reset(turnstileWidget);
  say('Working out what is in your stack…');
  try {
    const res = await resolve(body, token);
    say(res.droppedTransitive > 0 ? `Left out ${res.droppedTransitive} indirect dependencies with no known vulnerabilities.` : '');
    renderChips(res.chips);
  } catch (err) {
    if (err instanceof ApiError && err.fallback === 'manual') {
      say(err.message);
      renderChips([]);
    } else {
      say(err instanceof Error ? err.message : 'Something went wrong.');
    }
  }
}

// ---------- Confirm ----------

interface ChipState {
  chip: Chip;
  selected: string | null;
}

function renderChips(chips: Chip[], existing: string[] = []): void {
  clear(app);
  const state: ChipState[] = [
    ...existing.map((item) => ({ chip: { input: item, status: 'resolved' as const, item }, selected: item })),
    ...chips.map((chip) => ({ chip, selected: chip.status === 'resolved' ? chip.item! : null })),
  ];
  const list = h('ul', { class: 'chips', 'aria-label': 'Stack items' });

  const draw = () => {
    clear(list);
    state.forEach((s, i) => {
      const remove = h('button', { type: 'button', class: 'icon', 'aria-label': `Remove ${s.chip.input}`, onclick: () => (state.splice(i, 1), draw()) }, '×');
      let body: Node;
      if (s.chip.status === 'ambiguous') {
        const select = h('select', { 'aria-label': `Which ${s.chip.input}?` }, h('option', { value: '' }, `Which "${s.chip.input}"?`), (s.chip.alternatives ?? []).map((a) => h('option', { value: a.item, selected: s.selected === a.item }, `${a.label} (${a.item})`)));
        select.addEventListener('change', () => (s.selected = select.value || null));
        body = select;
      } else if (s.chip.status === 'unrecognised') {
        body = h('span', {}, h('s', {}, s.chip.input), h('span', { class: 'muted small' }, ' not recognised'));
      } else {
        body = h('span', {}, h('code', {}, s.selected!), s.chip.known === false ? h('span', { class: 'muted small' }, ' watching') : null);
      }
      list.append(h('li', { class: `chip ${s.chip.status}` }, body, remove));
    });
    if (state.length === 0) list.append(h('li', { class: 'muted' }, 'No items yet. Add some below.'));
  };
  draw();

  const addInput = h('input', { id: 'add-item', type: 'text', placeholder: 'npm:express@4.18.2 or p:cisco/ios_xe', autocomplete: 'off', spellcheck: 'false' }) as HTMLInputElement;
  const addForm = h(
    'form',
    {
      class: 'row add',
      onsubmit: (e: Event) => {
        e.preventDefault();
        try {
          for (const item of parseStack(addInput.value)) {
            const text = serializeStack([item]);
            state.push({ chip: { input: text, status: 'resolved', item: text }, selected: text });
          }
          addInput.value = '';
          say('');
          draw();
        } catch (err) {
          say(err instanceof StackFormatError ? err.message : 'That is not a valid item.');
        }
      },
    },
    h('label', { for: 'add-item', class: 'visually-hidden' }, 'Add an item'),
    addInput,
    h('button', { type: 'submit' }, 'Add'),
  );

  const confirm = h(
    'button',
    {
      type: 'button',
      class: 'primary',
      onclick: () => {
        const items: StackItem[] = state.flatMap((s) => (s.selected ? parseStack(s.selected) : []));
        if (items.length === 0) return say('Choose or add at least one item.');
        if (items.length > 200) return say('A stack can have at most 200 items. Self-host Vulnder for larger stacks.');
        navigate(serializeStack(items), 30);
      },
    },
    'Show vulnerabilities',
  );

  app.append(
    h(
      'section',
      { class: 'card', 'aria-labelledby': 'confirm-title' },
      h('h2', { id: 'confirm-title' }, 'Check your stack'),
      h('p', { class: 'muted' }, 'Remove anything wrong, pick the right match where there is a choice, and add what is missing. Items with nothing reported in the window are still watched.'),
      list,
      addForm,
      h('p', { class: 'muted small' }, 'Format: ', h('code', {}, 'ecosystem:package@version'), ' (npm, pypi, cargo, go, maven, nuget, composer, gem, hex, pub) or ', h('code', {}, 'p:vendor/product@version'), '.'),
      h('div', { class: 'row' }, h('button', { type: 'button', onclick: () => renderInput() }, 'Start over'), confirm),
    ),
  );
}

// ---------- Results ----------

function navigate(stack: string, days: number): void {
  const url = `/?s=${encodeURIComponent(stack)}${days === 30 ? '' : `&days=${days}`}`;
  history.pushState(null, '', url);
  void route();
}

async function renderResults(stack: string, days: number): Promise<void> {
  clear(app);
  say('Loading…');
  let feed: Feed;
  try {
    feed = await getFeed(stack, days);
  } catch (err) {
    say('');
    app.append(h('div', { class: 'card' }, h('h2', {}, 'That stack link did not work'), h('p', {}, err instanceof Error ? err.message : ''), h('button', { type: 'button', onclick: () => (history.pushState(null, '', '/'), renderInput()) }, 'Start again')));
    return;
  }
  say(`${feed.results.length} vulnerabilities found.`);
  document.title = `${feed.summary.exploited} exploited · ${config?.displayName ?? 'Vulnder'}`;

  const items = parseStack(feed.stack);
  const daySelect = h('select', { id: 'days', 'aria-label': 'Time window' }, [7, 30, 90].map((d) => h('option', { value: d, selected: d === feed.days }, `Last ${d} days`)));
  daySelect.addEventListener('change', () => navigate(feed.stack, Number(daySelect.value)));

  app.append(
    h(
      'section',
      { class: 'card summary', 'aria-labelledby': 'stack-title' },
      h('div', { class: 'row' }, h('h2', { id: 'stack-title' }, 'Your stack'), daySelect),
      h('ul', { class: 'chips compact' }, items.map((i) => h('li', { class: 'chip resolved' }, h('code', {}, serializeStack([i]))))),
      h('div', { class: 'row wrap' }, h('button', { type: 'button', onclick: () => renderChips([], items.map((i) => serializeStack([i]))) }, 'Edit stack'), copyButtons(feed)),
      feed.versionCheckUnavailable ? h('p', { class: 'notice' }, 'Version checks are unavailable right now, so every match is shown as a product match.') : null,
    ),
  );

  const headline = matchHeadline(feed.results.length, feed.days);
  app.append(
    h('section', { class: 'headline', 'aria-labelledby': 'match-title' }, h('h2', { id: 'match-title' }, headline.title), h('p', { class: 'muted' }, headline.subtitle)),
    renderChanges(feed),
  );
  for (const tier of ['exploited', 'likely', 'backlog'] as const) {
    const list = feed.results.filter((r) => r.tier === tier);
    app.append(
      h(
        'section',
        { class: `tier ${tier}`, 'aria-labelledby': `tier-${tier}` },
        h('h2', { id: `tier-${tier}` }, `${TIER_TITLE[tier]} `, h('span', { class: 'count' }, String(list.length))),
        h('p', { class: 'muted small' }, TIER_NOTE[tier]),
        list.length === 0 ? h('p', { class: 'muted' }, 'Nothing here.') : h('ol', { class: 'results' }, list.map(renderResult)),
      ),
    );
  }
  if (feed.watching.length > 0) {
    app.append(
      h(
        'section',
        { class: 'card', 'aria-labelledby': 'watching-title' },
        h('h2', { id: 'watching-title' }, 'Watching'),
        h('p', { class: 'muted' }, `No admirers in the last ${feed.days} days. The feed will pick up new issues.`),
        h('ul', { class: 'chips compact' }, feed.watching.map((w) => h('li', { class: 'chip' }, h('code', {}, w)))),
      ),
    );
  }
}

function renderChanges(feed: Feed): HTMLElement {
  return h(
    'section',
    { class: 'card changes', 'aria-labelledby': 'changes-title' },
    h('h2', { id: 'changes-title' }, 'What changed this week'),
    feed.changes.length === 0
      ? h('p', { class: 'muted' }, 'No changes in the last 7 days.')
      : h('ul', {}, feed.changes.map((c) => h('li', {}, h('time', { datetime: c.occurredAt }, c.occurredAt.slice(0, 10)), ' ', describeChange(c)))),
  );
}

function renderResult(r: Result): HTMLElement {
  const advisory = safeHref(r.links.advisory);
  const patch = safeHref(r.links.patch);
  const e = r.evidence;
  const evidence =
    r.tier === 'exploited'
      ? `On CISA KEV since ${e.kevAddedAt?.slice(0, 10)}${e.kevDueDate ? ` · federal due date ${e.kevDueDate.slice(0, 10)}` : ''}${e.knownRansomware ? ' · used in ransomware campaigns' : ''}`
      : e.epss !== null
        ? `EPSS ${pct(e.epss)}${e.epssPercentile !== null ? ` (${ordinal(Math.round(e.epssPercentile * 100))} percentile)` : ''}, predicted probability of exploitation in the next 30 days`
        : 'No EPSS score yet';
  return h(
    'li',
    { class: 'result' },
    h('div', { class: 'row wrap' }, h('h3', {}, advisory ? h('a', { href: advisory, rel: 'noreferrer noopener', target: '_blank' }, r.id) : r.id), h('span', { class: `badge ${r.confidence}` }, r.confidence === 'version_confirmed' ? 'Version confirmed' : 'Product match')),
    r.title ? h('p', { class: 'title' }, r.title) : null,
    h('p', { class: 'evidence' }, evidence),
    h('p', { class: 'small' }, 'Matched ', r.matched.flatMap((m, i) => [i > 0 ? ', ' : '', h('code', {}, m)])),
    r.fixedVersions.length > 0 ? h('p', { class: 'small' }, 'Fixed in ', h('strong', {}, r.fixedVersions.join(', '))) : null,
    h(
      'p',
      { class: 'small links' },
      advisory ? h('a', { href: advisory, rel: 'noreferrer noopener', target: '_blank' }, 'Advisory') : null,
      patch ? h('a', { href: patch, rel: 'noreferrer noopener', target: '_blank' }, 'Patch') : null,
      r.cvss ? h('span', { class: 'muted' }, `CVSS ${r.cvss.score.toFixed(1)}`) : null,
    ),
  );
}

function copyButtons(feed: Feed): HTMLElement {
  const badgeMd = `[![known-exploited CVEs](${feed.links.badge})](${feed.links.page})`;
  const items: [string, string][] = [
    ['Copy page link', feed.links.page],
    ['Copy Atom link', feed.links.atom],
    ['Copy JSON link', feed.links.json],
    ['Copy badge Markdown', badgeMd],
  ];
  return h(
    'div',
    { class: 'copy' },
    items.map(([label, value]) =>
      h('button', {
        type: 'button',
        onclick: async () => {
          try {
            await navigator.clipboard.writeText(value);
            say(`${label.replace('Copy ', '')} copied.`);
          } catch {
            window.prompt('Copy this:', value);
          }
        },
      }, label),
    ),
  );
}

// ---------- Footer ----------

async function renderFreshness(): Promise<void> {
  const el = document.getElementById('freshness');
  if (!el) return;
  try {
    const health = await getHealth();
    const names: Record<string, string> = { cve: 'CVE records', ghsa: 'GitHub advisories', kev: 'CISA KEV', epss: 'EPSS' };
    el.replaceChildren(
      'Data freshness: ',
      ...Object.entries(health.sources).flatMap(([k, s], i) => [
        i > 0 ? ' · ' : '',
        h('span', { class: s.health === 'ok' ? '' : 'stale' }, `${names[k] ?? k} ${s.lastSuccessAt ? ago(s.lastSuccessAt) : 'never'}${s.health === 'stale' ? ' (stale)' : ''}`),
      ]),
    );
  } catch {
    el.textContent = 'Data freshness unavailable.';
  }
}

async function route(): Promise<void> {
  const params = new URLSearchParams(location.search);
  const s = params.get('s');
  if (s) await renderResults(s, Number(params.get('days') ?? 30) || 30);
  else renderInput();
  app.focus();
}

window.addEventListener('popstate', () => void route());

config = await getConfig().catch(() => null);
if (config) document.querySelectorAll('[data-name]').forEach((n) => (n.textContent = config!.displayName));
await route();
void renderFreshness();
