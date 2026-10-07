import { parseManifest } from '../src/resolve/manifests';
import { identity, parseStack, serializeStack, StackFormatError, withMarks, type StackItem } from '../src/stack/format';
import { TURNSTILE_ACTION } from '../src/resolve/turnstile';
import { ApiError, getConfig, getFeed, getHealth, resolve, type AppConfig, type Feed, type Priority, type Result } from './api';
import { clear, h, safeHref } from './dom';
import {
  ago,
  byPriority,
  CHANGE_LABEL,
  changeCounts,
  componentGroups,
  cvssSeverity,
  eventDetail,
  formatScore,
  itemMarks,
  groupChanges,
  matchHeadline,
  ordinal,
  pct,
  preview,
  RISK,
  shortSummary,
  withItemMarks,
  type ChangeGroup,
  type ComponentGroup,
} from './format';

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
const PRIORITIES: Priority[] = ['act', 'attend', 'watch', 'track'];

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
      class: 'compose',
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
    h('label', { for: 'stack-text', class: 'compose-label' }, 'What do you run?'),
    textarea,
    h('div', { class: 'row' }, h('p', { id: 'stack-help', class: 'muted small' }, 'Describe it in your own words, with versions where you know them, or paste a manifest.'), counter),
    h(
      'div',
      { class: 'examples' },
      h('span', { class: 'muted small' }, 'Or try'),
      EXAMPLES.map((ex) =>
        h('button', { type: 'button', class: 'chip-button', onclick: () => ((textarea.value = ex.text), updateCounter(), textarea.focus()) }, ex.label),
      ),
    ),
    turnstileBox,
    submitButton,
  );

  app.append(form, drop);
  mountTurnstile(turnstileBox);
}

function mountTurnstile(box: HTMLElement): void {
  if (!config) return;
  const tryRender = () => {
    if (!window.turnstile) return void setTimeout(tryRender, 200);
    turnstileWidget = window.turnstile.render(box, {
      sitekey: config!.turnstileSiteKey,
      action: TURNSTILE_ACTION,
      callback: (token: string) => (turnstileToken = token),
      'expired-callback': () => (turnstileToken = null),
      'error-callback': () => (turnstileToken = null),
    });
  };
  tryRender();
}

// ---------- Loading ----------

const SVG_NS = 'http://www.w3.org/2000/svg';

function svg(tag: string, attrs: Record<string, string>, ...children: Element[]): SVGElement {
  const el = document.createElementNS(SVG_NS, tag) as SVGElement;
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  el.append(...children);
  return el;
}

/** The logo at work: the magnifier circles as if scanning while the heart beats. */
function loader(title: string, detail: string): HTMLElement {
  const mark = svg(
    'svg',
    { viewBox: '0 0 48 48', 'aria-hidden': 'true', focusable: 'false' },
    svg(
      'g',
      { class: 'lens', fill: 'currentColor' },
      svg('path', { 'fill-rule': 'evenodd', d: 'M20 3a17 17 0 1 0 0.01 0ZM20 8.5a11.5 11.5 0 1 1-0.01 0Z' }),
      svg('path', { d: 'M31.5 35.5l4-4 10 10a2.8 2.8 0 0 1-4 4Z' }),
      svg('path', {
        class: 'heart',
        d: 'M20 27.7C14.96 24.1 12.44 21.22 12.44 17.62 12.44 15.1 14.24 13.3 16.58 13.3 18.02 13.3 19.28 14.2 20 15.46 20.72 14.2 21.98 13.3 23.42 13.3 25.76 13.3 27.56 15.1 27.56 17.62 27.56 21.22 25.04 24.1 20 27.7Z',
      }),
    ),
  );
  return h('div', { class: 'loader' }, mark, h('div', {}, h('h2', {}, title), h('p', { class: 'muted' }, detail)));
}

/**
 * Shows the loader and hides the rest of the page until the returned function
 * is called. The page underneath is left intact, so a failed request can show
 * the form again as it was.
 */
function showBusy(title: string, detail: string): () => void {
  const el = loader(title, detail);
  app.setAttribute('aria-busy', 'true');
  app.prepend(el);
  return () => {
    el.remove();
    app.removeAttribute('aria-busy');
  };
}

/** Shown once on the results page after a submit, e.g. names that matched nothing. */
let pendingNote = '';

async function submit(body: { text: string } | { candidates: import('../src/resolve/types').Candidate[] }): Promise<void> {
  if (!turnstileToken) return say('Please wait for the verification check to finish, then try again.');
  const token = turnstileToken;
  turnstileToken = null;
  window.turnstile?.reset(turnstileWidget);
  say('Working out what is in your stack…');
  const done = showBusy('Reading your stack…', 'Picking out the software and devices you named.');
  try {
    const res = await resolve(body, token);
    done();
    const items = res.chips.flatMap((c) => c.items.map((i) => i.item));
    const unrecognised = res.chips.filter((c) => c.status === 'unrecognised').map((c) => c.input);
    const exposed = res.chips.filter((c) => c.items.some((i) => i.exposed)).map((c) => c.input);
    const notes = [
      unrecognised.length > 0 ? `Couldn't match: ${unrecognised.join(', ')}. Use "Edit stack" to add them by hand.` : '',
      exposed.length > 0 ? `Marked as internet-facing from your description: ${exposed.join(', ')}. Use "Edit stack" to change that.` : '',
      res.droppedTransitive > 0 ? `Left out ${res.droppedTransitive} indirect dependencies with no known vulnerabilities.` : '',
    ].filter(Boolean);
    if (items.length === 0) {
      say(notes.join(' ') || 'Nothing recognisable there.');
      return renderEdit([]);
    }
    const stack = parseStack(items.join(','));
    if (stack.length > 200) {
      say('That is more than 200 items. Trim the list, or self-host Vulnder for larger stacks.');
      return renderEdit(items);
    }
    pendingNote = notes.join(' ');
    navigate(serializeStack(stack), 30);
  } catch (err) {
    done();
    if (err instanceof ApiError && err.fallback === 'manual') {
      say(err.message);
      renderEdit([]);
    } else {
      say(err instanceof Error ? err.message : 'Something went wrong.');
    }
  }
}

// ---------- Edit ----------

function renderEdit(initial: string[]): void {
  clear(app);
  const items = [...new Set(initial)];
  const list = h('ul', { class: 'chips', 'aria-label': 'Stack items' });

  const draw = () => {
    clear(list);
    items.forEach((item, i) => {
      const { name, close, exposed } = itemMarks(item);
      list.append(
        h(
          'li',
          { class: `chip ${close ? 'close' : 'resolved'}` },
          h('code', {}, name),
          close ? h('span', { class: 'muted small' }, ' close match') : null,
          h(
            'button',
            {
              type: 'button',
              class: 'expose',
              'aria-pressed': String(exposed),
              'aria-label': `${name} is internet-facing`,
              title: 'Reachable from the internet. Bugs an attacker could reach on it rank higher.',
              onclick: () => ((items[i] = withItemMarks(name, { close, exposed: !exposed })), draw()),
            },
            'Internet-facing',
          ),
          h('button', { type: 'button', class: 'icon', 'aria-label': `Remove ${name}`, onclick: () => (items.splice(i, 1), draw()) }, '×'),
        ),
      );
    });
    if (items.length === 0) list.append(h('li', { class: 'muted' }, 'No items yet. Add some below.'));
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
          for (const item of parseStack(addInput.value)) items.push(serializeStack([withMarks(item, { exposed: item.exposed })]));
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

  const show = h(
    'button',
    {
      type: 'button',
      class: 'primary',
      onclick: () => {
        if (items.length === 0) return say('Add at least one item.');
        const stack: StackItem[] = parseStack(items.join(','));
        if (stack.length > 200) return say('A stack can have at most 200 items. Self-host Vulnder for larger stacks.');
        navigate(serializeStack(stack), 30);
      },
    },
    'Show vulnerabilities',
  );

  app.append(
    h(
      'section',
      { class: 'block', 'aria-labelledby': 'edit-title' },
      h('h2', { id: 'edit-title' }, 'Edit your stack'),
      h(
        'p',
        { class: 'muted' },
        'Remove anything that is not yours and add what is missing. Close matches are products your description loosely fits. Mark what the internet can reach, so bugs an attacker could get at there rank higher. Items with nothing reported are still watched.',
      ),
      list,
      addForm,
      h('p', { class: 'muted small' }, 'Format: ', h('code', {}, 'ecosystem:package@version'), ' (npm, pypi, cargo, go, maven, nuget, composer, gem, hex, pub) or ', h('code', {}, 'p:vendor/product@version'), '.'),
      h('div', { class: 'row' }, h('button', { type: 'button', onclick: () => renderInput() }, 'Start over'), show),
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
  say('Finding matches…');
  const done = showBusy('Finding matches…', 'Checking your stack against recent CVEs, CISA KEV and EPSS.');
  let feed: Feed;
  try {
    feed = await getFeed(stack, days);
    done();
  } catch (err) {
    done();
    say('');
    app.append(h('div', { class: 'block' }, h('h2', {}, 'That stack link did not work'), h('p', {}, err instanceof Error ? err.message : ''), h('button', { type: 'button', onclick: () => (history.pushState(null, '', '/'), renderInput()) }, 'Start again')));
    return;
  }
  say([`${feed.results.length} vulnerabilities found.`, pendingNote].filter(Boolean).join(' '));
  pendingNote = '';
  document.title = `${config?.displayName ?? 'Vulnder'}: ${feed.summary.exploited} exploited`;

  const items = parseStack(feed.stack);
  const daySelect = h('select', { id: 'days', 'aria-label': 'Time window' }, [7, 30, 90].map((d) => h('option', { value: d, selected: d === feed.days }, `Last ${d} days`)));
  daySelect.addEventListener('change', () => navigate(feed.stack, Number(daySelect.value)));

  app.append(
    h(
      'section',
      { class: 'block summary', 'aria-labelledby': 'stack-title' },
      h('div', { class: 'row' }, h('h2', { id: 'stack-title' }, 'Your stack'), daySelect),
      h(
        'ul',
        { class: 'chips compact' },
        items.map((i) =>
          h(
            'li',
            { class: `chip ${i.close ? 'close' : 'resolved'}`, title: i.close ? 'Close match' : null },
            h('code', {}, identity(i)),
            i.exposed ? h('span', { class: 'exposed-mark small' }, 'Internet-facing') : null,
          ),
        ),
      ),
      h('div', { class: 'row wrap' }, h('button', { type: 'button', onclick: () => renderEdit(items.map((i) => serializeStack([i]))) }, 'Edit stack'), copyButtons(feed)),
      feed.versionCheckUnavailable ? h('p', { class: 'notice' }, 'Version checks are unavailable right now, so every match is shown as a product match.') : null,
    ),
  );

  const headline = matchHeadline(feed.results.length, feed.days);
  app.append(
    h('section', { class: 'headline', 'aria-labelledby': 'match-title' }, h('h2', { id: 'match-title' }, headline.title), h('p', { class: 'muted' }, headline.subtitle)),
  );
  // Priorities at a glance, what to fix first, the week's changes, then every result.
  if (feed.results.length > 0) app.append(riskSummary(feed), renderFixFirst(feed));
  app.append(renderChanges(feed));
  if (feed.results.length > 0) {
    const view = h('div', { class: 'results-view', id: 'results' });
    const draw = (grouping: Grouping) => {
      clear(view);
      view.append(...(grouping === 'component' ? renderByComponent(componentGroups(feed.fixFirst, feed.results)) : renderByPriority(feed.results)));
    };
    app.append(groupingToggle(draw), view);
    draw(savedGrouping());
  }
  if (feed.watching.length > 0) {
    app.append(
      h(
        'section',
        { class: 'block', 'aria-labelledby': 'watching-title' },
        h('h2', { id: 'watching-title' }, 'Watching'),
        h('p', { class: 'muted' }, `No admirers in the last ${feed.days} days. The feed will pick up new issues.`),
        h('ul', { class: 'chips compact' }, feed.watching.map((w) => h('li', { class: 'chip' }, h('code', {}, itemMarks(w).name)))),
      ),
    );
  }
}

/** How many CVEs each priority tile links before pointing at the full list. */
const TILE_SHOWN = 3;

/**
 * A strip split by how many results sit at each priority, then one column per
 * priority with its count, meaning and links to the first few CVEs.
 */
function riskSummary(feed: Feed): HTMLElement {
  const groups = byPriority(feed.results);
  // The strip repeats the counts below, so screen readers skip it.
  const strip = h(
    'div',
    { class: 'risk-strip', 'aria-hidden': 'true' },
    PRIORITIES.filter((p) => feed.priorities[p] > 0).map((p) => h('span', { class: RISK[p].light, style: `flex-grow: ${feed.priorities[p]}` })),
  );
  const ledger = h(
    'ul',
    { class: 'risk-summary', 'aria-label': 'Results by priority' },
    PRIORITIES.map((p) => {
      const n = feed.priorities[p];
      const { shown, rest } = preview(groups[p], TILE_SHOWN);
      return h(
        'li',
        { class: `risk-tile ${RISK[p].light}${n === 0 ? ' empty' : ''}` },
        h('span', { class: 'risk-head' }, h('span', { class: 'risk-count' }, String(n)), h('span', { class: 'risk-label' }, RISK[p].label)),
        h('span', { class: 'risk-note small' }, RISK[p].note),
        shown.length > 0
          ? h(
              'ul',
              { class: 'tile-vulns small', 'aria-label': `${RISK[p].label} CVEs` },
              shown.map((r) => h('li', {}, externalLink(r.links.advisory, r.id))),
              rest > 0
                ? h('li', {}, h('button', { type: 'button', class: 'link', onclick: () => document.getElementById('results')?.scrollIntoView({ behavior: 'smooth' }) }, `+${rest} more below`))
                : null,
            )
          : null,
      );
    }),
  );
  return h('div', { class: 'risk' }, strip, ledger);
}

/** A link that opens in a new tab, or plain text when the URL isn't http(s). */
function externalLink(url: string | null, label: string): HTMLElement | string {
  const href = safeHref(url);
  return href ? h('a', { href, rel: 'noreferrer noopener', target: '_blank' }, label) : label;
}

/** How many fix-first items show before the rest fold away. */
const FIX_SHOWN = 5;

function renderFixFirst(feed: Feed): HTMLElement {
  const items = componentGroups(feed.fixFirst, feed.results);
  const list = (from: number, to: number) => h('ol', { class: 'fix-list', start: from + 1 }, items.slice(from, to).map(renderFixItem));
  return h(
    'section',
    { class: 'block fix-first', 'aria-labelledby': 'fix-title' },
    h('h2', { id: 'fix-title' }, 'Fix first'),
    h('p', { class: 'muted small' }, 'Each item in your stack, ranked by what fixing it removes: the most urgent priority first, then the total risk score of its CVEs.'),
    list(0, FIX_SHOWN),
    items.length > FIX_SHOWN ? h('details', { class: 'more' }, h('summary', {}, `Show ${items.length - FIX_SHOWN} more`), list(FIX_SHOWN, items.length)) : null,
  );
}

/** One stack item; expands to its CVEs with their links, so nobody has to hunt for them further down. */
function renderFixItem(g: ComponentGroup): HTMLElement {
  const worst = PRIORITIES.find((p) => g.counts[p] > 0) ?? 'track';
  const total = g.vulns.length;
  return h(
    'li',
    { class: `fix-item ${RISK[worst].light}` },
    h(
      'details',
      {},
      h(
        'summary',
        {},
        h('span', { class: 'rank', 'aria-hidden': 'true' }, String(g.rank)),
        h('code', {}, g.component),
        g.close ? h('span', { class: 'badge match-close' }, 'Close match') : null,
        g.exposed ? h('span', { class: 'badge exposed' }, 'Internet-facing') : null,
        h('span', { class: 'score', title: 'The risk scores of its CVEs, added up' }, `Total risk ${formatScore(g.score)}`),
        tally(g.counts),
        h('span', { class: 'small muted' }, g.fixable === total ? `${total === 1 ? 'Fix' : `Fixes for all ${total}`} available` : `${g.fixable} of ${total} with a fix`),
        h('span', { class: 'expand small' }, h('span', { class: 'when-closed' }, `Show ${total === 1 ? 'CVE' : `${total} CVEs`}`), h('span', { class: 'when-open' }, 'Hide')),
      ),
      h('ol', { class: 'briefs' }, g.results.map(renderBrief)),
    ),
  );
}

/** A CVE in a line or two: priority, linked ID, title, why, and the fix. */
function renderBrief(r: Result): HTMLElement {
  const light = RISK[r.priority].light;
  const advisory = safeHref(r.links.advisory);
  // Some vendors (MSRC) give one page for both; the ID already links to it.
  const patch = safeHref(r.links.patch) === advisory ? null : safeHref(r.links.patch);
  return h(
    'li',
    { class: `brief ${light}` },
    h('p', { class: 'row wrap' }, h('span', { class: `pill ${light}` }, RISK[r.priority].label), h('strong', {}, externalLink(r.links.advisory, r.id)), r.title ? h('span', { class: 'title' }, r.title) : null),
    h(
      'p',
      { class: 'small links' },
      r.reasons.length > 0 ? h('span', {}, r.reasons[0]) : null,
      r.fixedVersions.length > 0 ? h('span', {}, 'Fixed in ', h('strong', {}, r.fixedVersions.join(', '))) : h('span', { class: 'muted' }, 'No fixed version listed'),
      patch ? h('a', { href: patch, rel: 'noreferrer noopener', target: '_blank' }, 'Patch') : null,
    ),
  );
}

function tally(counts: Record<Priority, number>): HTMLElement {
  return h(
    'span',
    { class: 'tally' },
    PRIORITIES.filter((p) => counts[p] > 0).map((p) => h('span', { class: `pill ${RISK[p].light}` }, `${counts[p]} ${RISK[p].label.toLowerCase()}`)),
  );
}

type Grouping = 'risk' | 'component';
const GROUPING_KEY = 'vulnder:grouping';

function savedGrouping(): Grouping {
  try {
    return localStorage.getItem(GROUPING_KEY) === 'component' ? 'component' : 'risk';
  } catch {
    return 'risk';
  }
}

function groupingToggle(draw: (g: Grouping) => void): HTMLElement {
  const current = savedGrouping();
  const option = (value: Grouping, label: string) =>
    h(
      'label',
      { class: 'segment' },
      h('input', {
        type: 'radio',
        name: 'grouping',
        value,
        checked: value === current,
        onchange: () => {
          try {
            localStorage.setItem(GROUPING_KEY, value);
          } catch {
            // Private windows can refuse storage; the choice still applies now.
          }
          draw(value);
        },
      }),
      h('span', {}, label),
    );
  return h('fieldset', { class: 'grouping' }, h('legend', { class: 'small muted' }, 'Group results'), option('risk', 'By priority'), option('component', 'By component'));
}

function renderByPriority(results: Result[]): HTMLElement[] {
  const groups = byPriority(results);
  return PRIORITIES.map((p) =>
    h(
      'section',
      { class: `tier ${RISK[p].light}`, 'aria-labelledby': `tier-${p}` },
      h('h2', { id: `tier-${p}` }, h('span', { class: 'light', 'aria-hidden': 'true' }), `${RISK[p].label} `, h('span', { class: 'count' }, String(groups[p].length))),
      h('p', { class: 'muted small' }, RISK[p].note),
      groups[p].length === 0 ? h('p', { class: 'muted' }, 'Nothing here.') : h('ol', { class: 'results' }, groups[p].map(renderResult)),
    ),
  );
}

/** One collapsible group per stack item, in fix-first order; urgent groups start open. */
function renderByComponent(groups: ComponentGroup[]): HTMLElement[] {
  return groups.map((g) => {
    const worst = PRIORITIES.find((p) => g.counts[p] > 0) ?? 'track';
    return h(
      'details',
      { class: `component ${RISK[worst].light}`, open: g.counts.act + g.counts.attend > 0 },
      h(
        'summary',
        {},
        h('span', { class: 'rank', 'aria-hidden': 'true' }, String(g.rank)),
        h('code', {}, g.component),
        g.close ? h('span', { class: 'badge match-close' }, 'Close match') : null,
        g.exposed ? h('span', { class: 'badge exposed' }, 'Internet-facing') : null,
        h('span', { class: 'score', title: 'The risk scores of its CVEs, added up' }, `Total risk ${formatScore(g.score)}`),
        tally(g.counts),
      ),
      h('ol', { class: 'results' }, g.results.map(renderResult)),
    );
  });
}

/** How many change cards show before the rest fold away. */
const CHANGES_SHOWN = 8;

function renderChanges(feed: Feed): HTMLElement {
  const groups = groupChanges(feed.changes, feed.results);
  const section = h(
    'section',
    { class: 'block changes', 'aria-labelledby': 'changes-title' },
    h('h2', { id: 'changes-title' }, 'What changed this week'),
  );
  if (groups.length === 0) {
    section.append(h('p', { class: 'muted' }, 'No changes in the last 7 days.'));
    return section;
  }
  section.append(h('p', { class: 'muted small' }, changeCounts(groups)));
  section.append(h('ol', { class: 'change-list' }, groups.slice(0, CHANGES_SHOWN).map(renderChangeGroup)));
  if (groups.length > CHANGES_SHOWN) {
    const rest = groups.length - CHANGES_SHOWN;
    section.append(
      h(
        'details',
        { class: 'more' },
        h('summary', {}, `Show ${rest} more`),
        h('ol', { class: 'change-list' }, groups.slice(CHANGES_SHOWN).map(renderChangeGroup)),
      ),
    );
  }
  if (groups.some((g) => g.events.some((e) => e.type === 'epss_crossed'))) {
    section.append(h('p', { class: 'muted small' }, 'An EPSS jump is a rise in the predicted probability of exploitation in the next 30 days, not evidence of exploitation.'));
  }
  return section;
}

function renderChangeGroup(g: ChangeGroup): HTMLElement {
  const r = g.result;
  const advisory = safeHref(r?.links.advisory);
  const patch = safeHref(r?.links.patch);
  const summary = shortSummary(r?.summary ?? null);
  return h(
    'li',
    { class: `change ${RISK[r?.priority ?? 'track'].light}` },
    h(
      'ul',
      { class: 'events', 'aria-label': 'What happened' },
      g.events.map((e) => h('li', { class: `event ${e.type}` }, h('strong', {}, CHANGE_LABEL[e.type]), ' ', h('span', {}, eventDetail(e)))),
    ),
    h(
      'h3',
      {},
      advisory ? h('a', { href: advisory, rel: 'noreferrer noopener', target: '_blank' }, g.vulnId) : g.vulnId,
      g.title ? h('span', { class: 'title' }, ` ${g.title}`) : null,
    ),
    r
      ? h(
          'p',
          { class: 'small row wrap' },
          h('span', { class: `pill ${RISK[r.priority].light}` }, RISK[r.priority].label),
          h('span', { class: `badge match-${r.match}` }, r.match === 'exact' ? 'Exact match' : 'Close match'),
          h('span', {}, 'Matched ', r.matched.flatMap((m, i) => [i > 0 ? ', ' : '', h('code', {}, itemMarks(m).name)])),
        )
      : null,
    summary ? h('p', { class: 'small' }, summary) : null,
    r && (r.fixedVersions.length > 0 || advisory || patch)
      ? h(
          'p',
          { class: 'small links' },
          r.fixedVersions.length > 0 ? h('span', {}, 'Fixed in ', h('strong', {}, r.fixedVersions.join(', '))) : null,
          advisory ? h('a', { href: advisory, rel: 'noreferrer noopener', target: '_blank' }, 'Advisory') : null,
          patch ? h('a', { href: patch, rel: 'noreferrer noopener', target: '_blank' }, 'Patch') : null,
        )
      : null,
  );
}

function renderResult(r: Result): HTMLElement {
  const advisory = safeHref(r.links.advisory);
  const patch = safeHref(r.links.patch);
  const e = r.evidence;
  const light = RISK[r.priority].light;
  return h(
    'li',
    { class: `result ${light}` },
    h(
      'div',
      { class: 'row wrap' },
      h('span', { class: `pill ${light}` }, RISK[r.priority].label),
      h('span', { class: 'score', title: 'Risk score, 0 to 100: orders results within a priority' }, `Risk ${formatScore(r.score)}`),
      h('h3', {}, advisory ? h('a', { href: advisory, rel: 'noreferrer noopener', target: '_blank' }, r.id) : r.id),
    ),
    r.title ? h('p', { class: 'title' }, r.title) : null,
    r.reasons.length > 0 ? h('p', { class: 'why small' }, h('strong', {}, 'Why: '), r.reasons.join('; ')) : null,
    h(
      'p',
      { class: 'facts row wrap small' },
      r.cvss ? h('span', { class: 'badge' }, `CVSS ${r.cvss.score.toFixed(1)} ${cvssSeverity(r.cvss.score).toLowerCase()}`) : h('span', { class: 'badge muted' }, 'No CVSS'),
      e.epss !== null
        ? h(
            'span',
            { class: 'badge', title: 'Predicted probability of exploitation in the next 30 days' },
            `EPSS ${pct(e.epss)}${e.epssPercentile !== null ? `, ${ordinal(Math.round(e.epssPercentile * 100))} percentile` : ''}`,
          )
        : h('span', { class: 'badge muted' }, 'No EPSS yet'),
      e.knownRansomware ? h('span', { class: 'pill red' }, 'Ransomware') : null,
      h('span', { class: `badge match-${r.match}` }, r.match === 'exact' ? 'Exact match' : 'Close match'),
      h('span', { class: `badge ${r.confidence}` }, r.confidence === 'version_confirmed' ? 'Version confirmed' : 'Product match'),
    ),
    e.kevAddedAt
      ? h('p', { class: 'evidence' }, `On CISA KEV since ${e.kevAddedAt.slice(0, 10)}${e.kevDueDate ? `, federal due date ${e.kevDueDate.slice(0, 10)}` : ''}`)
      : null,
    h('p', { class: 'small' }, 'Matched ', r.matched.flatMap((m, i) => [i > 0 ? ', ' : '', h('code', {}, itemMarks(m).name)])),
    r.fixedVersions.length > 0 ? h('p', { class: 'small' }, 'Fixed in ', h('strong', {}, r.fixedVersions.join(', '))) : null,
    h(
      'p',
      { class: 'small links' },
      advisory ? h('a', { href: advisory, rel: 'noreferrer noopener', target: '_blank' }, 'Advisory') : null,
      patch ? h('a', { href: patch, rel: 'noreferrer noopener', target: '_blank' }, 'Patch') : null,
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
        i > 0 ? ', ' : '',
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
