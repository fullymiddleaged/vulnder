import { parseManifest } from '../src/resolve/manifests';
import { extractCveIds, looksLikeCveList, MAX_SCAN_BYTES } from '../src/resolve/cve-list';
import { identity, isCveItem, isTeam, MAX_CVE_ITEMS, parseStack, serializeStack, StackFormatError, withMarks, type StackItem } from '../src/stack/format';
import { guessTeam, isEdge, isEdgeDevice } from '../src/stack/teams';
import { MAX_MANIFEST_BYTES, MAX_TEXT_CHARS } from '../src/resolve/limits';
import { TURNSTILE_ACTION } from '../src/resolve/turnstile';
import { describeHours } from '../src/lib/time';
import {
  ApiError,
  getConfig,
  getFeed,
  getHealth,
  earnPass,
  getPass,
  oneAtATime,
  resolve,
  type AppConfig,
  type Feed,
  type PassStatus,
  type Priority,
  type Reason,
  type Result,
  type SupportNotice,
  type SupportState,
  type TargetedNotice,
} from './api';
import { clear, h, safeHref } from './dom';
import { indexable } from './url';
import { exportFileName, exportMarkdown, remediationSteps } from './export';
import { TEAM, TEAM_GROUPS, teamOf, type TeamGroup } from './teams';
import { capEntries, fileProblem, joinNotes, MANIFEST_FORMATS, SCAN_FORMATS, scanFileProblem, textProblem } from './upload';
import {
  checksServedText,
  sourceAge,
  sourcesStatus,
  byPriority,
  foldFamilies,
  CHANGE_LABEL,
  changeCounts,
  componentGroups,
  splitShown,
  cvssSeverity,
  eventDetail,
  formatScore,
  fullSummary,
  itemMarks,
  describeCveCount,
  describeLength,
  examplePlaceholder,
  listHeadline,
  groupChanges,
  lockRemaining,
  matchHeadline,
  passNotice,
  ordinal,
  pct,
  preview,
  RISK,
  shortSummary,
  stackSummary,
  supportByItem,
  supportLines,
  supportPriority,
  TARGETED_INTRO,
  targetedByItem,
  targetedCount,
  targetedStatus,
  turnstileSize,
  withItemMarks,
  type ChangeGroup,
  type ComponentGroup,
} from './format';

declare global {
  interface Window {
    turnstile?: {
      render(el: HTMLElement, opts: Record<string, unknown>): string;
      reset(id?: string): void;
      remove(id: string): void;
    };
  }
}

const EXAMPLES = [
  { label: 'SaaS app', text: 'Next.js 16 and React 19 on Vercel, a Hono API with Better Auth, Postgres 18 via Drizzle, Valkey for caching' },
  { label: 'AI app', text: 'FastAPI on Python 3.14, LangGraph agents, vLLM and Ollama serving models, LiteLLM gateway, Open WebUI, pgvector on Postgres 18' },
  { label: 'Cloud platform', text: 'Astro and a NestJS API on AWS: EKS with Cilium and Envoy Gateway, Aurora Postgres 18, Valkey, Keycloak SSO, OpenTelemetry into Grafana' },
  { label: 'Office network', text: 'FortiGate firewalls, Cisco Catalyst switches, Windows Server 2025 domain controllers, Exchange Server SE' },
  { label: 'AI coding agents', text: 'Claude Code and Cursor, MCP servers for GitHub, Playwright and Postgres, Ollama for local models, n8n automations' },
];
const MAX_TEXT = MAX_TEXT_CHARS;
const PRIORITIES: Priority[] = ['act', 'attend', 'watch', 'track'];

const app = document.getElementById('app')!;
const status = document.getElementById('status')!;
const DEFAULT_TITLE = document.title;
let config: AppConfig | null = null;
let turnstileToken: string | null = null;
let turnstileWidget: string | undefined;
/** Set when the verification widget fails or can't load, so submitting says so instead of waiting forever. */
let turnstileFailed = false;
/** This browser's allowance of different stacks this hour; null until known. */
let pass: PassStatus | null = null;

function say(message: string): void {
  status.textContent = message;
}

/** The current form's error line, next to the control that needs fixing; null on pages without a form. */
let formError: HTMLElement | null = null;

function errorSlot(): HTMLElement {
  formError = h('p', { class: 'form-error', role: 'alert', hidden: true });
  return formError;
}

/** A problem the person has to fix: shown by the form when there is one, else in the status line. `action` offers a way out. */
function report(message: string, action?: HTMLElement): void {
  if (formError?.isConnected) {
    formError.replaceChildren(message, ...(action ? [' ', action] : []));
    formError.hidden = !message;
    say('');
  } else say(message);
}

/** A cross, drawn rather than typed, for remove buttons. */
function crossIcon(): SVGElement {
  return svg('svg', { viewBox: '0 0 16 16', width: '16', height: '16', 'aria-hidden': 'true', focusable: 'false' }, svg('path', { d: 'M4 4l8 8M12 4l-8 8', stroke: 'currentColor', 'stroke-width': '2', 'stroke-linecap': 'round', fill: 'none' }));
}

/** Back to the empty form, with the page's own title, address and focus. */
function showInput(): void {
  if (location.search) history.pushState(null, '', '/');
  markIndexable();
  document.title = DEFAULT_TITLE;
  renderInput();
  app.focus();
}

async function refreshPass(): Promise<void> {
  pass = await getPass().catch(() => null);
}

const isLocked = () => lockRemaining(pass) !== null;
let lockTimer: ReturnType<typeof setInterval> | undefined;

/**
 * While this hour's allowance is spent: greys out the controls that would load
 * a stack and returns a red countdown to place next to them (null when not
 * locked). The controls still take clicks, to point at the countdown and say
 * why. When it reaches zero they work again and `onUnlock` runs.
 */
function lockControls(controls: (HTMLElement | null)[], onUnlock?: () => void): HTMLElement | null {
  clearInterval(lockTimer);
  if (!isLocked()) return null;
  const text = h('span', { class: 'countdown' });
  const notice = h('p', { class: 'notice locked', id: 'pass-notice' }, h('strong', {}, 'Usage limit reached. '), text);
  const owned = controls.filter((el): el is HTMLElement => el !== null);
  const refuse = (e: Event) => {
    if (!isLocked()) return;
    if (e instanceof KeyboardEvent && (e.key === 'Tab' || e.key === 'Shift')) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    nudge(notice);
  };
  for (const el of owned) {
    el.setAttribute('aria-disabled', 'true');
    el.setAttribute('aria-describedby', 'pass-notice');
    // Capture, so this runs before the control's own handler. A select opens on mousedown and changes by key.
    for (const type of ['click', 'mousedown', 'keydown', 'drop']) {
      if (type === 'click' || type === 'drop' || el instanceof HTMLSelectElement) el.addEventListener(type, refuse, { capture: true });
    }
  }
  const tick = () => {
    const message = passNotice(pass);
    if (message) return void (text.textContent = message);
    clearInterval(lockTimer);
    for (const el of owned) {
      el.removeAttribute('aria-disabled');
      el.removeAttribute('aria-describedby');
    }
    notice.remove();
    say('You can look up stacks again.');
    onUnlock?.();
  };
  tick();
  lockTimer = setInterval(() => (notice.isConnected ? tick() : clearInterval(lockTimer)), 1000);
  return notice;
}

/** Points at the countdown when someone tries a locked control. */
function nudge(notice: HTMLElement): void {
  say(passNotice(pass) ?? '');
  notice.classList.remove('nudge');
  void notice.offsetWidth; // restart the animation
  notice.classList.add('nudge');
  notice.scrollIntoView({ block: 'nearest', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
}

// ---------- Input ----------

/** The home form's two tabs: describe a stack, or rank a list of CVEs. `/#cves` opens the second. */
type InputTab = 'stack' | 'cves';
const CVE_TAB_HASH = '#cves';
const tabFromHash = (): InputTab => (location.hash === CVE_TAB_HASH ? 'cves' : 'stack');

/** For "Try an example": exploited, critical but not exploited, a rejected duplicate, a rejected ID and a typo. */
const CVE_EXAMPLE = ['CVE-2021-44228', 'CVE-2024-3400', 'CVE-2014-0160', 'CVE-2022-2422', 'CVE-2021-26940', 'CVE-2023-2004', 'CVE-2021-442288'].join('\n');

/**
 * The home form. Both tabs are built at once and one is hidden, so each keeps
 * what was typed in it and the verification widget is mounted only once.
 * `prefill` goes into the open tab's box.
 */
function renderInput(prefill = '', tab: InputTab = tabFromHash()): void {
  clear(app);
  const stackPanel = stackForm(tab === 'stack' ? prefill : '', () => select('cves', true));
  const cvePanel = cveForm(tab === 'cves' ? prefill : '');
  const panels: Record<InputTab, { el: HTMLElement; error: HTMLElement; field: HTMLTextAreaElement }> = { stack: stackPanel, cves: cvePanel };
  const tabButton = (id: InputTab, label: string) =>
    h('button', { type: 'button', role: 'tab', id: `tab-${id}`, class: 'tab', 'aria-controls': `panel-${id}` }, label) as HTMLButtonElement;
  const tabs: Record<InputTab, HTMLButtonElement> = { stack: tabButton('stack', 'By stack'), cves: tabButton('cves', 'By CVE list') };
  const order: InputTab[] = ['stack', 'cves'];
  const turnstileBox = h('div', { class: 'turnstile' });

  let current: InputTab = tab;
  /** Shows a tab. `carry` moves the stack box's text across (it read as a CVE list). */
  const select = (next: InputTab, carry = false, focusTab = false) => {
    if (carry) {
      panels.cves.field.value = panels.stack.field.value;
      panels.cves.field.dispatchEvent(new Event('input'));
    }
    current = next;
    for (const t of order) {
      const on = t === next;
      tabs[t].setAttribute('aria-selected', String(on));
      tabs[t].tabIndex = on ? 0 : -1;
      panels[t].el.hidden = !on;
    }
    formError = panels[next].error;
    report('');
    // The open tab is in the address, so it can be linked; nothing else about it is kept.
    const url = next === 'cves' ? `/${CVE_TAB_HASH}` : '/';
    if (location.pathname + location.hash !== url) history.replaceState(null, '', url);
    if (focusTab) tabs[next].focus();
    else if (carry) panels.cves.field.focus();
  };
  for (const t of order) tabs[t].addEventListener('click', () => select(t));

  // Arrow keys, Home and End move between tabs and open them (the WAI-ARIA tabs pattern).
  const tablist = h('div', { class: 'tabs', role: 'tablist', 'aria-label': 'What to check' }, tabs.stack, tabs.cves);
  tablist.addEventListener('keydown', (e) => {
    const at = order.indexOf(current);
    const to = { ArrowRight: at + 1, ArrowLeft: at - 1, Home: 0, End: order.length - 1 }[e.key];
    if (to === undefined) return;
    e.preventDefault();
    select(order[(to + order.length) % order.length]!, false, true);
  });

  app.append(
    h(
      'div',
      { class: 'compose-tabs' },
      tablist,
      // The countdown goes first, so it's seen before anything is typed.
      lockControls([stackPanel.submit, stackPanel.drop, cvePanel.submit, cvePanel.drop], () => (stackPanel.update(), cvePanel.update())),
      stackPanel.el,
      cvePanel.el,
      // One check for both tabs, beneath them: either tab's lookup spends the same hourly allowance.
      turnstileBox,
    ),
  );
  select(tab);
  mountTurnstile(turnstileBox);
}

interface Panel {
  el: HTMLElement;
  field: HTMLTextAreaElement;
  error: HTMLElement;
  submit: HTMLElement;
  drop: HTMLElement;
  /** Recounts the box and greys out the button to match. */
  update(): void;
}

/** A drop zone that hands its file, chosen or dropped, to `onFile`. */
function dropZone(id: string, accept: string, title: string, text: (HTMLElement | string)[], onFile: (file: File) => void): HTMLElement {
  const fileInput = h('input', { type: 'file', id, class: 'visually-hidden', accept }) as HTMLInputElement;
  const drop = h('div', { class: 'drop small', title }, h('p', {}, ...text), fileInput);
  fileInput.addEventListener('change', () => {
    const file = fileInput.files?.[0];
    // Cleared, so choosing the same file again (after an edit) reads it again.
    fileInput.value = '';
    if (file) onFile(file);
  });
  drop.addEventListener('dragover', (e) => {
    e.preventDefault();
    drop.classList.add('over');
  });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (e) => {
    e.preventDefault();
    drop.classList.remove('over');
    const file = e.dataTransfer?.files?.[0];
    if (file) onFile(file);
  });
  return drop;
}

/** The "By CVE list" tab: paste or drop a scan report; only the IDs it finds go into the link. */
function cveForm(prefill: string): Panel {
  const field = h('textarea', {
    id: 'cve-text',
    rows: 6,
    maxlength: 1_000_000,
    spellcheck: 'false',
    placeholder: 'CVE-2021-44228\nCVE-2024-3400\nCVE-2014-0160',
    'aria-describedby': 'cve-help cve-count',
  }) as HTMLTextAreaElement;
  field.value = prefill;
  const counter = h('span', { class: 'counter', id: 'cve-count' });
  const submit = h('button', { type: 'submit', class: 'primary', 'aria-describedby': 'cve-count' }, 'Rank CVEs');
  let ids: string[] = [];
  const update = () => {
    ids = extractCveIds(field.value).ids;
    const { label, over, empty } = describeCveCount(ids.length, MAX_CVE_ITEMS);
    counter.textContent = label;
    counter.classList.toggle('over', over);
    submit.toggleAttribute('disabled', over || empty);
    submit.textContent = empty || over ? 'Rank CVEs' : `Rank ${ids.length.toLocaleString('en')} ${ids.length === 1 ? 'CVE' : 'CVEs'}`;
  };
  field.addEventListener('input', update);
  update();

  const onFile = async (file: File) => {
    const problem = scanFileProblem(file.name, file.size);
    if (problem) return report(problem);
    const text = await file.text();
    if (text.includes('\0')) return report(`${file.name} isn't a text file. Export the report as CSV or XML.`);
    const found = extractCveIds(text).ids;
    if (found.length === 0) return report(`${file.name} has no CVE IDs in it.`);
    if (found.length > MAX_CVE_ITEMS) {
      return report(`${file.name} lists ${found.length.toLocaleString('en')} CVEs, and a list can have ${MAX_CVE_ITEMS.toLocaleString('en')}. Split the report, or filter it to the higher severities first.`);
    }
    report('');
    say(`Read ${found.length} CVE IDs from ${file.name}.`);
    await rankCves(found);
  };
  const drop = dropZone(
    'cve-file',
    '.csv,.tsv,.nessus,.xml,.json,.txt',
    `Up to ${MAX_SCAN_BYTES / 1_000_000} MB: ${SCAN_FORMATS}`,
    [
      'Have a scan report? Drop it here or ',
      h('label', { for: 'cve-file', class: 'link' }, 'choose a file'),
      '. ',
      h('span', { class: 'muted' }, 'Read in your browser: only the CVE IDs go into the link.'),
    ],
    (file) => void onFile(file),
  );
  const error = errorSlot();
  const el = h(
    'div',
    { role: 'tabpanel', id: 'panel-cves', 'aria-labelledby': 'tab-cves' },
    h(
      'form',
      {
        class: 'compose',
        onsubmit: (e: Event) => {
          e.preventDefault();
          update();
          if (ids.length === 0) return report('Paste some CVE IDs, or drop a scan report, first.');
          void rankCves(ids);
        },
      },
      h('label', { for: 'cve-text', class: 'compose-label' }, 'Which CVEs do you want to prioritise?'),
      field,
      h('div', { class: 'row' }, h('p', { id: 'cve-help', class: 'muted small' }, `Paste a scanner export (${SCAN_FORMATS}) or any list of CVE IDs. Up to ${MAX_CVE_ITEMS.toLocaleString('en')}, of any age.`), counter),
      h(
        'div',
        { class: 'examples' },
        h('span', { class: 'muted small' }, 'Or try'),
        h('button', { type: 'button', class: 'chip-button', onclick: () => ((field.value = CVE_EXAMPLE), update(), field.focus()) }, 'An example list'),
      ),
      drop,
      error,
      submit,
    ),
  );
  return { el, field, error, submit, drop, update };
}

/**
 * Ranks a list of CVE IDs. The verification check earns this browser its pass
 * first, so a list counts against the same hourly allowance as a stack; then
 * the IDs go straight to the feed, with nothing else sent. The form stays up
 * while the pass is checked, so a second click is dropped (see `sending`).
 */
function rankCves(ids: string[]): Promise<boolean> {
  return sending(() => sendCves(ids));
}

async function sendCves(ids: string[]): Promise<void> {
  if (isLocked()) return say(passNotice(pass) ?? '');
  const token = takeToken("The verification check couldn't run, so a list can't be ranked right now. Reload the page to try again.");
  if (!token) return;
  say('Checking…');
  try {
    pass = await earnPass(token);
  } catch (err) {
    say('');
    return report(err instanceof Error ? err.message : 'Something went wrong. Try again in a moment.');
  }
  if (isLocked()) return say(passNotice(pass) ?? '');
  pendingNotes = [];
  pendingUnmatched = 0;
  navigate(serializeStack(ids.map((id) => ({ kind: 'cve', id }))), 30);
}

/** The "Your stack" tab. `toCves` opens the CVE tab with this box's text, when it reads as a list of CVEs. */
function stackForm(prefill: string, toCves: () => void): Panel {
  const textarea = h('textarea', {
    id: 'stack-text',
    rows: 6,
    maxlength: 200_000,
    placeholder: examplePlaceholder(EXAMPLES),
    'aria-describedby': 'stack-help',
  }) as HTMLTextAreaElement;
  textarea.value = prefill;
  const counter = h('span', { class: 'counter', id: 'stack-length' });
  // Over the limit, the button stays greyed out, so a description that would be refused is never sent.
  const submitButton = h('button', { type: 'submit', class: 'primary', 'aria-describedby': 'stack-length' }, 'Find vulnerabilities');
  const helpText = 'Describe your whole stack in your own words. Include versions if you know them.';
  const help = h('p', { id: 'stack-help', class: 'muted small' }, helpText);
  // A pasted list of CVEs belongs in the other tab: say so, and offer to move it. Never moved unasked.
  const listHint = [h('strong', {}, 'This looks like a list of CVE IDs. '), h('button', { type: 'button', class: 'link', onclick: toCves }, 'Rank them as a CVE list')];
  let hinting = false;
  const updateCounter = () => {
    const manifest = !!parseManifest(textarea.value);
    const { label, over } = describeLength(textarea.value, manifest, MAX_TEXT);
    counter.textContent = label;
    counter.classList.toggle('over', over);
    submitButton.toggleAttribute('disabled', over);
    const hint = !manifest && looksLikeCveList(textarea.value, MAX_TEXT);
    if (hint !== hinting) help.replaceChildren(...(hint ? listHint : [helpText]));
    hinting = hint;
  };
  textarea.addEventListener('input', updateCounter);
  updateCounter();

  // One quiet line under the examples; the full list of formats is in the tooltip.
  const drop = dropZone(
    'file',
    '.json,.txt,.toml,.mod,.xml,.lock,Dockerfile,*',
    `Up to ${MAX_MANIFEST_BYTES / 1_000_000} MB: ${MANIFEST_FORMATS}`,
    [
      'Have a manifest? Drop it here or ',
      h('label', { for: 'file', class: 'link' }, 'choose a file'),
      '. ',
      h('span', { class: 'muted' }, 'Lockfiles, SBOMs, MCP configs and more, read in your browser: only package names and versions are sent.'),
    ],
    (file) => void onFile(file),
  );
  // Uploads skip the description's length limit: only the parsed names and versions are sent.
  const onFile = async (file: File) => {
    const problem = fileProblem(file.name, file.size);
    if (problem) return report(problem);
    const text = await file.text();
    const unusable = textProblem(file.name, text);
    if (unusable) return report(unusable);
    const manifest = parseManifest(text, file.name);
    if (!manifest) return report(`${file.name} isn't a manifest format Vulnder reads. Try ${MANIFEST_FORMATS}.`);
    if (manifest.candidates.length === 0) return report(manifest.note ?? `${file.name} lists no packages.`);
    report('');
    const { sent, note } = capEntries(manifest.candidates);
    say(`Read ${manifest.candidates.length} entries from ${file.name}.`);
    await submit({ candidates: sent }, joinNotes(manifest.note, note));
  };

  const error = errorSlot();
  const form = h(
    'form',
    {
      class: 'compose',
      onsubmit: (e: Event) => {
        e.preventDefault();
        const text = textarea.value.trim();
        if (!text) return report('Describe your stack, or upload a manifest, first.');
        const manifest = parseManifest(text);
        if (manifest) {
          if (manifest.candidates.length === 0) return report(manifest.note ?? 'That manifest lists no packages.');
          const { sent, note } = capEntries(manifest.candidates);
          return void submit({ candidates: sent }, joinNotes(manifest.note, note));
        }
        if (text.length > MAX_TEXT) return report(`Descriptions are limited to ${MAX_TEXT} characters. Shorten it, or upload a manifest file instead.`);
        void submit({ text });
      },
    },
    h('label', { for: 'stack-text', class: 'compose-label' }, 'What do you run?'),
    textarea,
    h('div', { class: 'row' }, help, counter),
    h(
      'div',
      { class: 'examples' },
      h('span', { class: 'muted small' }, 'Or try'),
      EXAMPLES.map((ex) =>
        h('button', { type: 'button', class: 'chip-button', onclick: () => ((textarea.value = ex.text), updateCounter(), textarea.focus()) }, ex.label),
      ),
    ),
    drop,
    error,
    submitButton,
  );
  const el = h('div', { role: 'tabpanel', id: 'panel-stack', 'aria-labelledby': 'tab-stack' }, form);
  return { el, field: textarea, error, submit: submitButton, drop, update: updateCounter };
}

/** How long to wait for the verification script before calling it unavailable. */
const TURNSTILE_WAIT_MS = 15_000;

function mountTurnstile(box: HTMLElement): void {
  // The last form's widget went with its page, and can no longer say when its
  // token expires: drop both, so a submit waits for this widget's own token.
  try {
    if (turnstileWidget) window.turnstile?.remove(turnstileWidget);
  } catch {
    // Already gone; nothing to tidy.
  }
  turnstileWidget = undefined;
  turnstileToken = null;
  turnstileFailed = false;
  if (!config) return void (turnstileFailed = true);
  const started = Date.now();
  const tryRender = () => {
    if (!box.isConnected) return;
    if (!window.turnstile) {
      if (Date.now() - started > TURNSTILE_WAIT_MS) return void (turnstileFailed = true);
      return void setTimeout(tryRender, 200);
    }
    turnstileWidget = window.turnstile.render(box, {
      sitekey: config!.turnstileSiteKey,
      action: TURNSTILE_ACTION,
      size: turnstileSize(box.clientWidth),
      callback: (token: string) => ((turnstileToken = token), (turnstileFailed = false)),
      'expired-callback': () => (turnstileToken = null),
      'error-callback': () => ((turnstileToken = null), (turnstileFailed = true)),
    });
  };
  tryRender();
}

/** Offered when free text can't be read: the verification check failed or the model is unavailable. */
function addByHandButton(): HTMLElement {
  return h('button', { type: 'button', class: 'link', onclick: () => (renderEdit([]), app.focus()) }, 'Add items by hand instead');
}

// ---------- Loading ----------

const SVG_NS = 'http://www.w3.org/2000/svg';

function svg(tag: string, attrs: Record<string, string>, ...children: Element[]): SVGElement {
  const el = document.createElementNS(SVG_NS, tag) as SVGElement;
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  el.append(...children);
  return el;
}

/** What a feed load checks, ticked off in turn under the loader. */
const FEED_STEPS = [
  'CVE records, with CISA’s exploitation assessments',
  'GitHub security advisories',
  'CISA Known Exploited Vulnerabilities',
  'EPSS exploit predictions',
  'OSV, to confirm affected versions',
  'Exact and close matches, ranked by what to fix first',
];
/** A list of CVEs is looked up by ID, so its checklist names what ranks them. */
const LIST_TITLE = 'Ranking your CVEs…';
const LIST_DETAIL = 'Looking up each CVE, whatever its age, in:';
const LIST_STEPS = [
  'CVE records, with CISA’s exploitation assessments',
  'CISA Known Exploited Vulnerabilities',
  'EPSS exploit predictions',
  'Rejected and duplicate CVEs',
  'Your CVEs, ranked by what to fix first',
];

/** True for a stack that is only a list of CVEs; false for anything else, a bad link included. */
function isList(stack: string): boolean {
  try {
    return parseStack(stack).every(isCveItem);
  } catch {
    return false;
  }
}

/** A description's lookup reads it first, then checks the feed: one checklist for both. */
const READ_STEP = 'Reading your stack';
const FEED_TITLE = 'Finding matches…';
const FEED_DETAIL = 'Checking your stack against these sources, for exact and close matches:';
/** How long each step shows while the request runs; the last one waits for the answer. */
const STEP_MS = 2000;
/** Once the answer is in, the steps left tick off this quickly, slow enough to read each one, even on a fast answer. */
const STEP_FINISH_MS = 450;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** The logo at work: the magnifier circles as if scanning while the broken shield's right half swings on its crack. */
function loader(title: string, detail: string, steps: HTMLElement | null): HTMLElement {
  const mark = svg(
    'svg',
    { viewBox: '0 0 48 48', 'aria-hidden': 'true', focusable: 'false' },
    svg(
      'g',
      { class: 'lens', fill: 'currentColor' },
      svg('path', { 'fill-rule': 'evenodd', d: 'M20 3a17 17 0 1 0 0.01 0ZM20 8.5a11.5 11.5 0 1 1-0.01 0Z' }),
      svg('path', { d: 'M31.5 35.5l4-4 10 10a2.8 2.8 0 0 1-4 4Z' }),
      svg('path', { d: 'M18.34 11.74L12.23 13.9L12.23 19.36C12.23 23.73 15.05 26.79 18.74 28.71L19.38 24.58L17.35 21.42L19.83 18.11L17.68 15.37Z' }),
      svg('path', {
        class: 'crack',
        d: 'M22.06 11.8L28.25 14.88L27.58 20.3C27.07 24.49 24.1 27.14 20.39 28.62L21.57 24.46L20.16 21.54L23.11 18.47L21.04 15.05Z',
      }),
    ),
  );
  return h('div', { class: 'loader' }, mark, h('div', {}, h('h2', {}, title), h('p', { class: 'muted' }, detail), steps));
}

interface Busy {
  el: HTMLElement;
  /** Ticks off the current step and starts timing the ones after it. */
  next(): void;
  /** `done(true)` ticks off the rest before the loader goes; `done()` removes it at once. */
  done(complete?: boolean): Promise<void>;
}

/** A submit's loader, kept on screen for the results page to carry on with. */
let handoff: Busy | null = null;

/**
 * Shows the loader and hides the rest of the page until `done` is called. The
 * page underneath is left intact, so a failed request can show the form again
 * as it was. With steps, one is ticked off every STEP_MS while waiting; with
 * `timed` false the first step waits for `next()` instead, for a request of
 * its own.
 */
function showBusy(title: string, detail: string, steps: readonly string[] = [], timed = true): Busy {
  const rows = steps.map((s) => h('li', { class: 'step' }, s));
  let at = 0;
  const mark = (i: number, state: 'active' | 'done') => {
    rows[i]?.setAttribute('data-state', state);
    if (state === 'active') rows[i]?.setAttribute('aria-current', 'step');
    else rows[i]?.removeAttribute('aria-current');
  };
  const advance = () => {
    mark(at, 'done');
    mark(++at, 'active');
  };
  mark(0, 'active');
  let timer: ReturnType<typeof setInterval> | undefined;
  const time = () => (timer = setInterval(() => at < rows.length - 1 && advance(), STEP_MS));
  if (timed) time();
  const el = loader(title, detail, rows.length > 0 ? h('ol', { class: 'steps small' }, rows) : null);
  app.setAttribute('aria-busy', 'true');
  app.prepend(el);
  const next = () => {
    clearInterval(timer);
    if (at < rows.length - 1) advance();
    time();
  };
  const done = async (complete = false) => {
    clearInterval(timer);
    if (complete && rows.length > 0) {
      while (at < rows.length - 1) {
        await sleep(STEP_FINISH_MS);
        advance();
      }
      await sleep(STEP_FINISH_MS);
      mark(at, 'done');
      await sleep(STEP_FINISH_MS);
    }
    el.remove();
    app.removeAttribute('aria-busy');
  };
  return { el, next, done };
}

/** Shown on the results page after a submit, e.g. names that matched nothing; cleared once shown. */
let pendingNotes: string[] = [];
/** How many names in that submit resolved to nothing, so a no-match headline doesn't overclaim. */
let pendingUnmatched = 0;

/**
 * The verification check's token, used once: the widget resets for the next
 * submit. Null, with the reason shown, while the check is still running or
 * when it couldn't run (`failed` says what that stops, `action` offers a way out).
 */
function takeToken(failed: string, action?: HTMLElement): string | null {
  if (!turnstileToken) {
    if (turnstileFailed) report(failed, action);
    else report('Please wait a moment for the verification check to finish, then try again.');
    return null;
  }
  const token = turnstileToken;
  turnstileToken = null;
  window.turnstile?.reset(turnstileWidget);
  report('');
  return token;
}

/**
 * One lookup at a time, from either tab. Each send also spends the single-use
 * verification token, so a repeat that slipped through would be refused anyway;
 * this keeps it from being sent at all.
 */
const sending = oneAtATime();

/** Sends a description or parsed entries; `note` (e.g. what a big file left out) shows with the results. */
function submit(body: { text: string } | { candidates: import('../src/resolve/types').Candidate[] }, note = ''): Promise<boolean> {
  return sending(() => sendStack(body, note));
}

async function sendStack(body: { text: string } | { candidates: import('../src/resolve/types').Candidate[] }, note: string): Promise<void> {
  if (isLocked()) return say(passNotice(pass) ?? '');
  const token = takeToken("The verification check couldn't run, so a description can't be read right now. Reload the page to try again.", addByHandButton());
  if (!token) return;
  say('Working out what is in your stack…');
  const busy = showBusy(FEED_TITLE, FEED_DETAIL, [READ_STEP, ...FEED_STEPS], false);
  try {
    const res = await resolve(body, token);
    const items = res.chips.flatMap((c) => c.items.map((i) => i.item));
    const unrecognised = res.chips.filter((c) => c.status === 'unrecognised').map((c) => c.input);
    const teamed = res.chips.some((c) => c.items.some((i) => i.team));
    const notes = [
      note,
      unrecognised.length > 0 ? `Couldn't match: ${unrecognised.join(', ')}. These weren't checked; use Edit stack to add them by hand.` : '',
      teamed ? 'Your description reads as an enterprise stack, so each item has a team and results can be grouped by team. Use Edit stack to change a team.' : '',
      res.droppedTransitive > 0 ? `Left out ${res.droppedTransitive} indirect dependencies with no known vulnerabilities.` : '',
    ].filter(Boolean);
    if (items.length === 0) {
      void busy.done();
      renderEdit([]);
      report(notes.join(' ') || 'Nothing recognisable there. Add items by hand below.');
      return void app.focus();
    }
    const stack = parseStack(items.join(','));
    if (stack.length > 200) {
      void busy.done();
      renderEdit(items);
      report('That is more than 200 items. Trim the list, or self-host Vulnder for larger stacks.');
      return void app.focus();
    }
    pendingNotes = notes;
    pendingUnmatched = unrecognised.length;
    // Read: tick it off and leave the loader up, for the results page to carry on through the sources.
    busy.next();
    handoff = busy;
    navigate(serializeStack(stack), 30);
  } catch (err) {
    void busy.done();
    if (err instanceof ApiError && err.fallback === 'manual') {
      renderEdit([]);
      report(err.message);
      app.focus();
    } else if (err instanceof ApiError && err.reason === 'timeout') {
      // The description stays in the box, so trying again costs nothing.
      report(err.message, addByHandButton());
    } else {
      report(err instanceof Error ? err.message : 'Something went wrong. Try again in a moment.');
    }
  }
}

// ---------- Edit ----------

/**
 * `support`: the last feed's support findings by item name, so items with paid extended support on offer get a Has ESU tick.
 * `listed`: the stack's CVE IDs (`cve:` items), kept in a folded group of their own.
 */
function renderEdit(initial: string[], support: ReadonlyMap<string, SupportNotice> = new Map(), listed: string[] = []): void {
  clear(app);
  const items = [...new Set(initial)];
  const cves = [...new Set(listed)];
  // Teams belong to enterprise stacks: once a stack has them, every item gets a team picker.
  const teamed = items.some((i) => itemMarks(i).team !== null);
  const list = h('ul', { class: 'chips', 'aria-label': 'Stack items' });

  const teamPicker = (i: number) => {
    const { name, team, ...marks } = itemMarks(items[i]!);
    const select = h(
      'select',
      { class: 'team-select', 'aria-label': `Team for ${name}` },
      TEAM_GROUPS.map((t) => h('option', { value: t === 'unassigned' ? '' : t, selected: (team ?? 'unassigned') === t }, TEAM[t].label)),
    );
    select.addEventListener('change', () => {
      items[i] = withItemMarks(name, { ...marks, team: isTeam(select.value) ? select.value : null });
    });
    return select;
  };

  // Products only. Ticked means "faces the internet"; the link keeps a tag only
  // where the user disagrees with what the product is.
  const edgeToggle = (i: number) => {
    let parsed: StackItem | undefined;
    try {
      parsed = parseStack(items[i]!)[0];
    } catch {
      return null;
    }
    if (parsed?.kind !== 'product') return null;
    const { name, ...marks } = itemMarks(items[i]!);
    const byProduct = isEdgeDevice(parsed);
    const box = h('input', { type: 'checkbox', checked: isEdge(parsed) }) as HTMLInputElement;
    box.addEventListener('change', () => {
      items[i] = withItemMarks(name, { ...marks, edge: box.checked === byProduct ? null : box.checked });
    });
    return h('label', { class: 'edge-toggle small', title: 'Faces the internet: a VPN, firewall, gateway or anything else reachable from outside' }, box, ' Edge device');
  };

  // Only where it changes something: a release past its end that paid extended support can cover.
  const esuToggle = (i: number) => {
    const { name, ...marks } = itemMarks(items[i]!);
    const n = support.get(name);
    if (!n || !(marks.esu || n.esu || n.esuUntil)) return null;
    const box = h('input', { type: 'checkbox', checked: marks.esu }) as HTMLInputElement;
    box.addEventListener('change', () => {
      items[i] = withItemMarks(name, { ...marks, esu: box.checked });
    });
    return h('label', { class: 'edge-toggle small', title: 'You pay for extended security updates (Microsoft ESU, Red Hat ELS, SUSE LTSS, Ubuntu Pro), so it’s covered until those end' }, box, ' Has ESU');
  };

  const draw = () => {
    clear(list);
    items.forEach((item, i) => {
      const { name, close } = itemMarks(item);
      list.append(
        h(
          'li',
          { class: `chip ${close ? 'close' : 'resolved'}` },
          h('code', {}, name),
          close ? h('span', { class: 'close-mark small' }, 'Close match') : null,
          edgeToggle(i),
          esuToggle(i),
          teamed ? teamPicker(i) : null,
          h('button', { type: 'button', class: 'icon', 'aria-label': `Remove ${name}`, onclick: () => (items.splice(i, 1), draw()) }, crossIcon()),
        ),
      );
    });
    if (items.length === 0) list.append(h('li', { class: 'muted' }, cves.length > 0 ? 'No components. Your CVE list is below.' : 'No items yet. Add some below.'));
    drawCves();
  };
  const cveList = h('ul', { class: 'chips compact', 'aria-label': 'CVEs from your list' });
  const cveSummary = h('summary', { class: 'small' });
  const cveGroup = h('details', { class: 'stack-items listed-ids', open: cves.length <= STACK_SHOWN }, cveSummary, cveList);
  const drawCves = () => {
    cveGroup.hidden = cves.length === 0;
    cveSummary.textContent = `${cveCount(cves.length)} from your list`;
    cveList.replaceChildren(
      ...cves.map((id, i) =>
        h('li', { class: 'chip resolved' }, h('code', {}, id), h('button', { type: 'button', class: 'icon', 'aria-label': `Remove ${id}`, onclick: () => (cves.splice(i, 1), drawCves()) }, crossIcon())),
      ),
    );
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
            if (item.kind === 'cve') {
              if (!cves.includes(item.id)) cves.push(item.id);
              continue;
            }
            // In a stack with teams, an item added by hand starts with the fixed table's guess.
            const team = item.team ?? (teamed ? (guessTeam(item) ?? undefined) : undefined);
            items.push(serializeStack([withMarks(item, { team })]));
          }
          addInput.value = '';
          report('');
          draw();
        } catch (err) {
          report(err instanceof StackFormatError ? err.message : 'That is not a valid item.');
        }
      },
    },
    h('label', { for: 'add-item', class: 'visually-hidden' }, 'Add an item'),
    addInput,
    h('button', { type: 'submit' }, 'Add'),
  );

  const startOver = h('button', { type: 'button', onclick: showInput }, 'Start over');
  const show = h(
    'button',
    {
      type: 'button',
      class: 'primary',
      onclick: () => {
        if (items.length + cves.length === 0) return report('Add at least one item.');
        const stack: StackItem[] = items.length > 0 ? parseStack(items.join(',')) : [];
        if (stack.length > 200) return report('A stack can have at most 200 items. Self-host Vulnder for larger stacks.');
        navigate(serializeStack([...stack, ...cves.map((id) => ({ kind: 'cve' as const, id }))]), 30);
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
        'Remove anything that is not yours and add what is missing. Exact matches are the products you named. Close matches are products your description loosely fits, so check they are yours. Tick Edge device for anything the internet can reach directly; Vulnder ticks VPNs, firewalls and gateways for you, and you can untick one that sits inside your network. Tick Has ESU on a release past its end of support if you pay for extended security updates. Items with nothing reported are still watched.',
      ),
      list,
      cveGroup,
      addForm,
      h('p', { class: 'muted small' }, 'Format: ', h('code', {}, 'ecosystem:package@version'), ' (npm, pypi, cargo, go, maven, nuget, composer, gem, hex, pub) or ', h('code', {}, 'p:vendor/product@version'), '. Not sure of the name? Go back and describe it in words instead.'),
      errorSlot(),
      h('div', { class: 'row' }, startOver, show),
      lockControls([startOver, show]),
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
  const at = routes;
  // After a submit, its loader stays exactly as it is (no second fade-in) and carries on.
  let busy = handoff;
  handoff = null;
  if (busy?.el.isConnected) {
    for (const child of [...app.children]) if (child !== busy.el) child.remove();
  } else {
    void busy?.done();
    clear(app);
    busy = null;
  }
  clearInterval(lockTimer);
  say(FEED_TITLE);
  busy ??= isList(stack) ? showBusy(LIST_TITLE, LIST_DETAIL, LIST_STEPS) : showBusy(FEED_TITLE, FEED_DETAIL, FEED_STEPS);
  let feed: Feed;
  try {
    feed = await getFeed(stack, days);
    await busy.done(true);
  } catch (err) {
    void busy.done();
    // Left for another page while it failed: that page stays, without this error under it.
    if (at !== routes) return;
    say('');
    if (err instanceof ApiError && err.reason === 'pass-limit') {
      // Answered from the lock cookie, without a database read.
      await refreshPass();
      const retry = h('button', { type: 'button', class: 'primary', onclick: () => void route() }, 'Load this stack');
      const notice = lockControls([retry]);
      app.append(
        h(
          'div',
          { class: 'block' },
          h('h2', {}, 'Please wait before loading a stack'),
          notice ?? h('p', {}, err.message),
          h('p', { class: 'muted' }, 'Nothing loads until the countdown ends, including stacks you have already opened. Your link stays the same, so come back to it then.'),
          retry,
        ),
      );
      return;
    }
    if (err instanceof ApiError && (err.reason === 'timeout' || err.reason === 'network')) {
      // Stuck or offline, not a bad link: the same link can simply be tried again.
      const retry = h('button', { type: 'button', class: 'primary', onclick: () => void route() }, 'Try again');
      app.append(h('div', { class: 'block' }, h('h2', {}, 'No answer from Vulnder'), h('p', {}, err.message), retry));
      return;
    }
    app.append(h('div', { class: 'block' }, h('h2', {}, 'That stack link did not work'), h('p', {}, err instanceof Error ? err.message : ''), h('button', { type: 'button', onclick: showInput }, 'Start again')));
    return;
  }
  // Loading this stack may have used the allowance; editing is greyed out once it has.
  await refreshPass();
  // Left for another page while it loaded: that page stays.
  if (at !== routes) return;
  const notes = pendingNotes;
  const unmatched = pendingUnmatched;
  pendingNotes = [];
  pendingUnmatched = 0;
  say(`${feed.results.length} vulnerabilities found.`);
  document.title = `${config?.displayName ?? 'Vulnder'}: ${feed.summary.exploited} exploited`;

  // The answer first: the headline with ways to share and follow it, the stack it answers for, priorities
  // at a glance, what to fix first, the week's changes, every result, then share and follow again in full.
  const listOnly = isList(feed.stack);
  const unranked = (feed.listed?.rejected.length ?? 0) + (feed.listed?.notFound.length ?? 0);
  const headline = listOnly
    ? listHeadline(feed.priorities, unranked)
    : matchHeadline(feed.results.filter((r) => r.confidence !== 'listed').length, feed.days, unmatched, feed.results.filter((r) => r.beforeWindow && r.confidence !== 'listed').length);
  app.append(
    h(
      'section',
      { class: 'headline', 'aria-labelledby': 'match-title' },
      h('h2', { id: 'match-title' }, headline.title),
      h('p', { class: 'muted' }, headline.subtitle),
      h('div', { class: 'share-bar row wrap', role: 'group', 'aria-label': 'Share and follow' }, copyButtons(feed), exportButtons(feed)),
    ),
    renderStack(feed, notes),
  );
  // What became of the IDs that aren't ranked, before the ranking itself.
  const aboutList = renderListed(feed);
  if (aboutList) app.append(aboutList);
  // Before the CVEs: out of support outweighs any one of them, and a stack can have it with none.
  const support = renderSupport(feed);
  if (support) app.append(support);
  // Also before the CVEs, and also a finding about the item: it can hold even when no CVE matched.
  const targeted = renderTargeted(feed);
  if (targeted) app.append(targeted);
  if (feed.results.length > 0) app.append(riskSummary(feed), renderFixFirst(feed));
  app.append(renderChanges(feed));
  if (feed.results.length > 0) {
    const view = h('div', { class: 'results-view', id: 'results', tabindex: -1 });
    const groups = componentGroups(feed.fixFirst, feed.results);
    // Only an enterprise stack carries teams; without them, "By team" isn't offered.
    const teamed = groups.some((g) => g.team !== null);
    const draw = (grouping: Grouping) => {
      clear(view);
      if (grouping === 'risk') view.append(...renderByPriority(feed.results));
      else if (grouping === 'component') view.append(...renderByComponent(groups));
      else view.append(...renderByTeam(groups));
    };
    const initial = savedGrouping(teamed);
    app.append(h('div', { class: 'results-head' }, groupingToggle(draw, initial, teamed), h('a', { href: '/how-it-works#ranking', class: 'small' }, 'How results are ranked')), view);
    draw(initial);
  }
  // Items out of support or losing it show above, not as quietly watched.
  const flagged = supportByItem(feed.support ?? []);
  const watching = feed.watching.filter((w) => {
    const n = flagged.get(itemMarks(w).name);
    return !n || n.state === 'covered';
  });
  if (watching.length > 0) {
    app.append(
      h(
        'section',
        { class: 'block', 'aria-labelledby': 'watching-title' },
        h('h2', { id: 'watching-title' }, 'Watching'),
        h('p', { class: 'muted' }, `No admirers in the last ${feed.days} days. The feed will pick up new issues.`),
        h('ul', { class: 'chips compact' }, watching.map((w) => h('li', { class: 'chip' }, h('code', {}, itemMarks(w).name)))),
      ),
    );
  }
  app.append(renderShare(feed));
}

/** Short stacks show their items; long ones (a lockfile) fold them away behind the summary. */
const STACK_SHOWN = 12;

/**
 * The stack these results answer for, in one line with its time window and Edit,
 * then what the lookup couldn't do (names it couldn't match, what it marked).
 * Those notes stay on the page rather than passing through the status line.
 */
function renderStack(feed: Feed, notes: string[]): HTMLElement {
  const all = parseStack(feed.stack);
  const items = all.filter((i) => !isCveItem(i));
  const cves = all.filter(isCveItem).map((c) => c.id);
  if (items.length === 0) return renderListStack(cves, notes);
  const daySelect = h('select', { id: 'days', 'aria-label': 'Time window' }, [7, 30, 90].map((d) => h('option', { value: d, selected: d === feed.days }, `Last ${d} days`)));
  daySelect.addEventListener('change', () => {
    // A key press can still get through on some browsers; put the window back.
    if (isLocked()) return void (daySelect.value = String(feed.days));
    navigate(feed.stack, Number(daySelect.value));
  });
  const editButton = h(
    'button',
    { type: 'button', id: 'edit-stack', onclick: () => (renderEdit(items.map((i) => serializeStack([i])), supportByItem(feed.support ?? []), cves), app.focus()) },
    'Edit stack',
  );
  // Once this hour's stacks are used, nothing loads: not another stack, and not another window of this one.
  const editNotice = lockControls([editButton, daySelect]);
  const anyClose = items.some((i) => i.close);
  const allNotes = [
    ...notes,
    feed.versionCheckUnavailable ? 'Version checks are unavailable right now, so every match shows as "Version not confirmed".' : '',
  ].filter(Boolean);
  return h(
    'section',
    { class: 'block stack', 'aria-labelledby': 'stack-title' },
    h(
      'div',
      { class: 'row wrap' },
      h('h2', { id: 'stack-title', class: 'stack-title' }, 'Your stack'),
      h('span', { class: 'muted' }, stackSummary(items), cves.length > 0 ? `, plus ${cveCount(cves.length)} from your list` : ''),
      h('span', { class: 'stack-actions' }, daySelect, editButton),
    ),
    h(
      'p',
      { class: 'muted small' },
      'Whatever the window, known-exploited, likely-exploited and CVSS 9.9+ CVEs from the last year show too, as a safety net.',
      cves.length > 0 ? ' The window doesn’t apply to the CVEs you listed: they all show, whatever their age.' : '',
    ),
    editNotice,
    allNotes.length > 0 ? h('ul', { class: 'notice notes', 'aria-label': 'About this lookup' }, allNotes.map((n) => h('li', {}, n))) : null,
    h(
      'details',
      { class: 'stack-items', open: items.length <= STACK_SHOWN },
      h('summary', { class: 'small' }, h('span', { class: 'when-closed' }, `Show the ${items.length} items`), h('span', { class: 'when-open' }, 'Hide the items')),
      h(
        'ul',
        { class: 'chips compact' },
        items.map((i) =>
          h(
            'li',
            { class: `chip ${i.close ? 'close' : 'resolved'}` },
            h('code', {}, identity(i)),
            i.close ? h('span', { class: 'close-mark small' }, 'Close match') : null,
            isEdge(i) ? edgeBadge() : null,
            i.esu ? h('span', { class: 'team-mark small muted', title: 'You pay for extended security updates' }, 'Has ESU') : null,
            i.team ? h('span', { class: 'team-mark small muted' }, TEAM[i.team].label) : null,
          ),
        ),
      ),
      anyClose
        ? h('p', { class: 'muted small' }, 'Exact matches are the products you named. Close matches are products your description loosely fits: check they are yours, and remove any that aren’t with Edit stack.')
        : null,
    ),
    cves.length > 0 ? listedIds(cves, `${cveCount(cves.length)} from your list`) : null,
  );
}

const cveCount = (n: number) => `${n.toLocaleString('en')} ${n === 1 ? 'CVE' : 'CVEs'}`;

/** A list's IDs, folded away behind one line. */
function listedIds(ids: string[], label: string): HTMLElement {
  return h(
    'details',
    { class: 'stack-items listed-ids', open: ids.length <= STACK_SHOWN },
    h('summary', { class: 'small' }, h('span', { class: 'when-closed' }, `Show the ${label}`), h('span', { class: 'when-open' }, `Hide the ${label}`)),
    h('ul', { class: 'chips compact' }, ids.map((id) => h('li', { class: 'chip resolved' }, h('code', {}, id)))),
  );
}

/**
 * The stack line for a stack that is only a list of CVEs. There's no window
 * to choose (every listed CVE shows), and Edit list reopens the CVE tab with
 * the IDs in it.
 */
function renderListStack(cves: string[], notes: string[]): HTMLElement {
  const editButton = h(
    'button',
    {
      type: 'button',
      id: 'edit-stack',
      onclick: () => {
        history.pushState(null, '', `/${CVE_TAB_HASH}`);
        markIndexable();
        document.title = DEFAULT_TITLE;
        renderInput(cves.join('\n'), 'cves');
        app.focus();
      },
    },
    'Edit list',
  );
  const editNotice = lockControls([editButton]);
  return h(
    'section',
    { class: 'block stack', 'aria-labelledby': 'stack-title' },
    h('div', { class: 'row wrap' }, h('h2', { id: 'stack-title', class: 'stack-title' }, 'Your CVE list'), h('span', { class: 'muted' }, cveCount(cves.length)), h('span', { class: 'stack-actions' }, editButton)),
    h('p', { class: 'muted small' }, 'Every CVE you listed is looked up, whatever its age.'),
    editNotice,
    notes.length > 0 ? h('ul', { class: 'notice notes', 'aria-label': 'About this lookup' }, notes.map((n) => h('li', {}, n))) : null,
    listedIds(cves, cveCount(cves.length)),
  );
}

/**
 * What became of the listed IDs that aren't ranked: rejected as a duplicate
 * (its replacement ranks in its place), rejected outright, or not a published
 * CVE at all. Null when every ID is ranked.
 */
function renderListed(feed: Feed): HTMLElement | null {
  const { rejected = [], notFound = [] } = feed.listed ?? {};
  if (rejected.length === 0 && notFound.length === 0) return null;
  const ranked = new Set(feed.results.map((r) => r.id));
  const id = (cve: string) => h('code', {}, cve);
  const joined = (ids: string[], each: (cve: string) => HTMLElement) => ids.flatMap((c, i) => [i === 0 ? '' : i === ids.length - 1 ? ' and ' : ', ', each(c)]);
  const duplicates = rejected.filter((r) => r.replacedBy.length > 0);
  const dropped = rejected.filter((r) => r.replacedBy.length === 0).map((r) => r.id);
  return h(
    'section',
    { class: 'block listed', 'aria-labelledby': 'listed-title' },
    h('h2', { id: 'listed-title' }, 'About your list'),
    h(
      'ul',
      { class: 'listed-notes', role: 'list' },
      duplicates.map((r) => {
        const shown = r.replacedBy.filter((c) => ranked.has(c));
        return h(
          'li',
          {},
          id(r.id),
          ` was rejected as a duplicate of `,
          ...joined(r.replacedBy, id),
          shown.length === 0 ? '.' : shown.length === r.replacedBy.length ? `, ranked below in its place.` : ', ranked below where published.',
        );
      }),
      dropped.length > 0
        ? h(
            'li',
            {},
            ...joined(dropped, id),
            dropped.length === 1 ? ' was rejected with no replacement named, so there is nothing to fix under that ID.' : ' were rejected with no replacement named, so there is nothing to fix under those IDs.',
          )
        : null,
      notFound.length > 0
        ? h(
            'li',
            {},
            notFound.length === 1 ? '1 ID isn’t a published CVE: ' : `${notFound.length} IDs aren’t published CVEs: `,
            ...joined(notFound, id),
            '. Reserved and never published, or mistyped.',
          )
        : null,
    ),
  );
}

/**
 * Items whose vendor no longer supports them, or soon won't: no fix will come for their next CVE,
 * so they rank with Act now or Attend whatever their CVEs. Null when there are none.
 */
function renderSupport(feed: Feed): HTMLElement | null {
  const notices = feed.support ?? [];
  if (notices.length === 0) return null;
  const out = notices.some((n) => n.state === 'eol');
  return h(
    'section',
    { class: 'block support', 'aria-labelledby': 'support-title' },
    h('h2', { id: 'support-title' }, out ? 'Out of support' : 'Vendor support'),
    h(
      'p',
      { class: 'muted small' },
      'Past its vendor’s end of support, software gets no more security fixes, so every new bug in it stays open. Out of support ranks with Act now, and support ending within 90 days with Attend, whatever its CVEs. Dates from ',
      externalLink('https://endoflife.date', 'endoflife.date'),
      '.',
    ),
    h('ul', { class: 'support-list', role: 'list' }, notices.map(renderNotice)),
  );
}

function renderNotice(n: SupportNotice): HTMLElement {
  const p = supportPriority(n.state);
  const light = p ? RISK[p].light : 'grey';
  const lines = supportLines(n);
  return h(
    'li',
    { class: `support-item ${light}` },
    h('p', { class: 'row wrap' }, h('span', { class: `pill ${light}` }, p ? RISK[p].label : 'Covered'), h('strong', {}, n.name), n.edge ? edgeBadge() : null),
    lines.map((l) => h('p', { class: 'small' }, l)),
    n.source === 'cve' && n.cve
      ? h('p', { class: 'small' }, 'Its vendor said it is no longer supported in ', externalLink(`https://www.cve.org/CVERecord?id=${encodeURIComponent(n.cve)}`, n.cve), '.')
      : null,
    h('p', { class: 'small muted' }, n.items.length === 1 ? 'Stack item: ' : 'Stack items: ', n.items.flatMap((i, k) => [k > 0 ? ', ' : '', h('code', {}, itemMarks(i).name)])),
  );
}

function supportBadge(state: SupportState): HTMLElement | null {
  if (state === 'covered') return null;
  return h(
    'span',
    { class: `badge support ${state}`, title: 'Its vendor no longer ships security fixes for it, or stops within 90 days. See Out of support above.' },
    state === 'eol' ? 'Out of support' : 'Support ending',
  );
}

/**
 * Items whose CVEs CISA added to KEV in the last 90 days, whatever version they affect: attackers
 * are working on that product. A finding about the item that ranks nothing, so it carries no
 * tier colour (DESIGN.md, the Risk Colour Rule). Null when there are none.
 */
function renderTargeted(feed: Feed): HTMLElement | null {
  const notices = feed.targeted ?? [];
  if (notices.length === 0) return null;
  return h(
    'section',
    { class: 'block targeted', 'aria-labelledby': 'targeted-title' },
    h('h2', { id: 'targeted-title' }, 'Targeted by attackers'),
    h('p', { class: 'muted small' }, TARGETED_INTRO),
    h('ul', { class: 'targeted-list', role: 'list' }, notices.map((n) => renderTargetedItem(n, feed.results))),
  );
}

function renderTargetedItem(n: TargetedNotice, results: readonly Result[]): HTMLElement {
  const latest = n.kev[0]!;
  const names = n.items.map((i) => itemMarks(i).name);
  return h(
    'li',
    { class: 'targeted-item' },
    // A listed CVE's product goes by its name, as its Fix first row does.
    n.label
      ? h('p', { class: 'row wrap' }, h('strong', { class: 'product-name' }, n.label), h('code', { class: 'small muted' }, names[0]!))
      : h('p', {}, names.flatMap((name, k) => [k > 0 ? ', ' : '', h('code', {}, name)])),
    h(
      'p',
      { class: 'small' },
      `CISA added ${targetedCount(n)} to KEV, most recently `,
      externalLink(`https://www.cve.org/CVERecord?id=${encodeURIComponent(latest.id)}`, latest.id),
      ` on ${latest.addedAt}. `,
      targetedStatus(n, results),
    ),
  );
}

function targetedBadge(): HTMLElement {
  return h(
    'span',
    { class: 'badge targeted', title: 'CISA added CVEs in this product to KEV in the last 90 days. See Targeted by attackers above.' },
    'Targeted',
  );
}

/** Links that keep showing this stack's latest results, and exports of them as they are now. */
function renderShare(feed: Feed): HTMLElement {
  return h(
    'section',
    { class: 'block share', 'aria-labelledby': 'share-title' },
    h('h2', { id: 'share-title' }, 'Share and follow'),
    h(
      'p',
      { class: 'muted small' },
      'The page link and Atom feed always show the latest results for this stack, so you can come back or subscribe. Export for AI saves the results as they are now, as a Markdown file an AI agent can work through to apply the fixes.',
    ),
    h('div', { class: 'row wrap' }, copyButtons(feed), exportButtons(feed)),
  );
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
        h('span', { class: 'risk-note small' }, RISK[p].brief),
        h('span', { class: 'risk-window small' }, RISK[p].window),
        shown.length > 0
          ? h(
              'ul',
              { class: 'tile-vulns small', 'aria-label': `${RISK[p].label} CVEs` },
              shown.map((r) => h('li', {}, externalLink(r.links.advisory, r.id))),
              rest > 0 ? h('li', {}, h('button', { type: 'button', class: 'link', onclick: jumpToResults }, `+${rest} more below`)) : null,
            )
          : null,
      );
    }),
  );
  return h('div', { class: 'risk' }, strip, ledger, glossary());
}

/** Moves to the full results, smoothly unless motion is reduced, and takes focus there so keyboard and screen reader users land too. */
function jumpToResults(): void {
  const results = document.getElementById('results');
  if (!results) return;
  results.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
  results.focus({ preventScroll: true });
}

/** The terms the results use, in plain words, one click away rather than only in tooltips. */
function glossary(): HTMLElement {
  const terms: [string, string][] = [
    ['KEV', 'CISA’s Known Exploited Vulnerabilities catalog: bugs with evidence of real attacks. It outranks every other signal.'],
    ['EPSS', 'FIRST’s predicted chance that a bug is exploited in the next 30 days. A forecast, not evidence. The percentile compares it with every other CVE.'],
    ['LEV', 'NIST’s estimate, from a bug’s EPSS history, of the chance it has already been exploited. A lower bound, not evidence.'],
    ['CVSS', 'A 0–10 severity score: how bad a bug would be if used, not whether anyone is using it.'],
    ['Risk score', 'A 0–100 score that orders results within a priority. Total risk adds up a component’s scores. Neither is a probability.'],
    ['Exact or close match', 'An exact match is a product you named. A close match is one your description loosely fits: check it is yours.'],
    ['Version confirmed', 'Your version is in the affected range. "Version not confirmed" means only the product matched, so compare your version with "Fixed in".'],
  ];
  return h(
    'details',
    { class: 'glossary small' },
    h('summary', {}, 'What KEV, EPSS, CVSS and the other terms mean'),
    h('dl', {}, terms.flatMap(([term, meaning]) => [h('dt', {}, term), h('dd', {}, meaning)])),
  );
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
  const shown = new Set<string>();
  const targeted = targetedByItem(feed.targeted ?? []);
  const isTargeted = (g: ComponentGroup) => targeted.has(g.component) || g.also.some((i) => targeted.has(itemMarks(i).name));
  // role=list: Safari drops list semantics from a list styled without markers, and here the order is the point.
  const list = (from: number, to: number) =>
    h('ol', { class: 'fix-list', role: 'list', start: from + 1 }, items.slice(from, to).map((g) => renderFixItem(g, shown, isTargeted(g))));
  return h(
    'section',
    { class: 'block fix-first', 'aria-labelledby': 'fix-title' },
    h('h2', { id: 'fix-title' }, 'Fix first'),
    h(
      'p',
      { class: 'muted small' },
      items.every((g) => g.listed)
        ? 'Your CVEs grouped by product, ranked by what patching each one removes: the most urgent priority first, then the total risk score of its CVEs.'
        : `Each item in your stack${items.some((g) => g.listed) ? ', and the products your listed CVEs are in,' : ''} ranked by what fixing it removes: the most urgent priority first, then the total risk score of its CVEs.`,
    ),
    items.some((g) => g.close || g.also.some((i) => itemMarks(i).close))
      ? h(
          'p',
          { class: 'muted small' },
          'Broad names like “Windows” bring in close matches that share most of their CVEs. Remove the ones you don’t run to tighten this list: ',
          // The stack's own Edit button, so a used-up pass refuses it the same way.
          h('button', { type: 'button', class: 'link', onclick: () => document.getElementById('edit-stack')?.click() }, 'Edit stack'),
          '.',
        )
      : null,
    list(0, FIX_SHOWN),
    items.length > FIX_SHOWN ? h('details', { class: 'more' }, h('summary', {}, `Show ${items.length - FIX_SHOWN} more`), list(FIX_SHOWN, items.length)) : null,
  );
}

/**
 * One stack item (or several with the same CVEs); expands to its CVEs with their links, so nobody has
 * to hunt for them further down. CVEs an earlier row already showed are listed by ID only.
 */
function renderFixItem(g: ComponentGroup, shown: Set<string>, targeted = false): HTMLElement {
  const worst = worstOf(g);
  const total = g.vulns.length;
  const { fresh, repeated } = splitShown(g.results, shown);
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
        groupName(g).flatMap((part, i) => (i === 0 ? [part] : [pause(), part])),
        groupIsEdge(g) ? [pause(), edgeBadge()] : null,
        g.support ? [pause(), supportBadge(g.support)] : null,
        targeted ? [pause(), targetedBadge()] : null,
        pause(),
        tally(g.counts),
        pause(),
        // A listed CVE names no version the stack runs, so there's no fixed version to count.
        g.listed ? null : [h('span', { class: 'small muted' }, g.fixable === total ? `${total === 1 ? 'Fix' : `Fixes for all ${total}`} available` : `${g.fixable} of ${total} with a fix`), pause()],
        h('span', { class: 'score', title: 'The risk scores of its CVEs, added up' }, `Total risk ${formatScore(g.score)}`),
        pause(),
        h('span', { class: 'expand small' }, h('span', { class: 'when-closed' }, `Show ${total === 1 ? 'CVE' : `${total} CVEs`}`), h('span', { class: 'when-open' }, 'Hide')),
      ),
      sameCves(g),
      fresh.length > 0 ? h('ol', { class: 'briefs' }, fresh.map(renderBrief)) : null,
      listedAbove(repeated),
    ),
  );
}

/**
 * A row's name and its marks. Close matches merged into one row go by their shared name, so the
 * row doesn't read as one SKU (Server Core) the user may not run.
 */
function groupName(g: ComponentGroup): HTMLElement[] {
  // A listed group: its product's name, else the one CVE it holds.
  if (g.listed && g.label) return [h('strong', { class: 'product-name' }, g.label), h('code', { class: 'small muted' }, g.component)];
  if (g.listed && g.component.startsWith('cve:')) return [h('code', {}, `CVE-${g.component.slice(4)}`)];
  if (g.family) return [h('code', {}, g.family), h('span', { class: 'badge match-close' }, `${g.also.length + 1} close matches`)];
  return [
    h('code', {}, g.component),
    g.also.length > 0 ? h('span', { class: 'small muted' }, `+${g.also.length} more`) : null,
    g.close ? h('span', { class: 'badge match-close' }, 'Close match') : null,
  ].filter((e) => e !== null);
}

/** The other items sharing a row, each with its close-match mark; under a family name, every member. */
function sameCves(g: ComponentGroup): HTMLElement | null {
  if (g.also.length === 0) return null;
  if (g.family) {
    const names = [g.component, ...g.also.map((item) => itemMarks(item).name)].map((n) => h('code', {}, n));
    return h('p', { class: 'small muted also' }, 'Covers: ', names.flatMap((n, i) => (i === 0 ? [n] : [', ', n])));
  }
  const names = g.also.map((item) => {
    const { name, close } = itemMarks(item);
    return [h('code', {}, name), close ? ' (close match)' : ''];
  });
  return h('p', { class: 'small muted also' }, 'With the same CVEs: ', names.flatMap((n, i) => (i === 0 ? n : [', ', ...n])));
}

/** CVEs an earlier row showed in full, by linked ID. */
function listedAbove(repeated: Result[]): HTMLElement | null {
  if (repeated.length === 0) return null;
  const n = repeated.length;
  return h(
    'p',
    { class: 'small muted listed-above' },
    `${n === 1 ? '1 more CVE' : `${n} more CVEs`}, shown above: `,
    repeated.flatMap((r, i) => (i === 0 ? [externalLink(r.links.advisory, r.id)] : [', ', externalLink(r.links.advisory, r.id)])),
  );
}

/** A row's most urgent priority: its CVEs', or what its vendor support ranks with when that's higher. */
function worstOf(g: ComponentGroup): Priority {
  const byCves = PRIORITIES.find((p) => g.counts[p] > 0) ?? 'track';
  const bySupport = g.support ? supportPriority(g.support) : null;
  return bySupport && PRIORITIES.indexOf(bySupport) < PRIORITIES.indexOf(byCves) ? bySupport : byCves;
}

function groupIsEdge(g: ComponentGroup): boolean {
  return [g.item, ...g.also].some(isEdgeItem);
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
    // One line per CVE, so every row's pill and ID line up: a long title is clipped, in full on hover and in the results below.
    h('p', { class: 'row head' }, h('span', { class: `pill ${light}` }, RISK[r.priority].label), h('strong', {}, externalLink(r.links.advisory, r.id)), r.title ? h('span', { class: 'title', title: r.title }, r.title) : null),
    h(
      'p',
      { class: 'small links' },
      r.why.decisive ? h('span', {}, r.why.decisive.text) : r.reasons.length > 0 ? h('span', {}, r.reasons[0]) : null,
      r.fixedVersions.length > 0
        ? h('span', {}, 'Fixed in ', h('strong', {}, r.fixedVersions.join(', ')))
        : r.confidence === 'listed'
          ? null
          : h('span', { class: 'muted' }, 'No fixed version listed'),
      r.replaces?.length ? h('span', { class: 'muted' }, `Replaces ${r.replaces.join(', ')}`) : null,
      patch ? h('a', { href: patch, rel: 'noreferrer noopener', target: '_blank' }, 'Patch') : null,
    ),
  );
}

/** A VPN, edge firewall, gateway or ADC, or whatever the user ticked: the same test the server ranks with (src/stack/teams.ts). */
function isEdgeItem(item: string): boolean {
  try {
    const parsed = parseStack(item)[0];
    return !!parsed && isEdge(parsed);
  } catch {
    return false;
  }
}

function edgeBadge(): HTMLElement {
  return h(
    'span',
    { class: 'badge edge', title: 'Faces the internet, so CISA’s deadlines for internet-facing systems apply and its CVEs rank ahead of similar ones. Change it under Edit stack.' },
    'Edge device',
  );
}

/** A comma only screen readers hear, so a row of badges reads as a list rather than one run-on phrase. */
function pause(): HTMLElement {
  return h('span', { class: 'visually-hidden' }, ', ');
}

function tally(counts: Record<Priority, number>): HTMLElement {
  return h(
    'span',
    { class: 'tally' },
    PRIORITIES.filter((p) => counts[p] > 0).map((p) => h('span', { class: `pill ${RISK[p].light}` }, `${counts[p]} ${RISK[p].label.toLowerCase()}`)),
  );
}

const GROUPINGS = ['risk', 'component', 'team'] as const;
type Grouping = (typeof GROUPINGS)[number];
const GROUPING_KEY = 'vulnder:grouping';

/** The grouping chosen last time, if this stack can show it. */
function savedGrouping(teamed: boolean): Grouping {
  try {
    const saved = GROUPINGS.find((g) => g === localStorage.getItem(GROUPING_KEY)) ?? 'risk';
    return saved === 'team' && !teamed ? 'risk' : saved;
  } catch {
    return 'risk';
  }
}

function groupingToggle(draw: (g: Grouping) => void, current: Grouping, teamed: boolean): HTMLElement {
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
  return h(
    'fieldset',
    { class: 'grouping' },
    h('legend', { class: 'small muted' }, 'Group results'),
    option('risk', 'By priority'),
    option('component', 'By component'),
    teamed ? option('team', 'By team') : null,
  );
}

/** One section per priority that has results; the ledger above already shows the empty ones as 0. */
function renderByPriority(results: Result[]): HTMLElement[] {
  const groups = byPriority(results);
  return PRIORITIES.filter((p) => groups[p].length > 0).map((p) =>
    h(
      'section',
      { class: `tier ${RISK[p].light}`, 'aria-labelledby': `tier-${p}` },
      h('h2', { id: `tier-${p}` }, h('span', { class: 'light', 'aria-hidden': 'true' }), `${RISK[p].label} `, h('span', { class: 'count' }, String(groups[p].length))),
      h('p', { class: 'muted small' }, RISK[p].note, ' ', h('strong', { class: 'window' }, `${RISK[p].window}.`)),
      renderList(groups[p]),
    ),
  );
}

/** One collapsible group per stack item, in fix-first order; urgent groups start open. */
function renderByComponent(groups: ComponentGroup[]): HTMLElement[] {
  const shown = new Set<string>();
  return groups.map((g) => renderComponent(g, shown));
}

/** Like a fix-first row: CVEs an earlier group showed in full are listed by ID only. */
function renderComponent(g: ComponentGroup, shown: Set<string>): HTMLElement {
  const worst = worstOf(g);
  const { fresh, repeated } = splitShown(g.results, shown);
  return h(
    'details',
    { class: `component ${RISK[worst].light}`, open: worst === 'act' || worst === 'attend' },
    h(
      'summary',
      {},
      h('span', { class: 'rank', 'aria-hidden': 'true' }, String(g.rank)),
      groupName(g),
      groupIsEdge(g) ? edgeBadge() : null,
      g.support ? supportBadge(g.support) : null,
      h('span', { class: 'score', title: 'The risk scores of its CVEs, added up' }, `Total risk ${formatScore(g.score)}`),
      tally(g.counts),
    ),
    sameCves(g),
    fresh.length > 0 ? renderList(fresh) : null,
    listedAbove(repeated),
  );
}

/**
 * The fix-first list split by the team that looks after each item, so work can be handed out.
 * Teams come in the order of their most urgent item; inside a team, fix-first order holds.
 * Unassigned, items with no team, always comes last.
 */
function renderByTeam(groups: ComponentGroup[]): HTMLElement[] {
  const byTeam = new Map<TeamGroup, ComponentGroup[]>();
  for (const g of groups) {
    const team = teamOf(g.item);
    byTeam.set(team, [...(byTeam.get(team) ?? []), g]);
  }
  const teams = TEAM_GROUPS.filter((t) => byTeam.has(t)).sort((a, b) => (a === 'unassigned' ? 1 : b === 'unassigned' ? -1 : byTeam.get(a)![0]!.rank - byTeam.get(b)![0]!.rank));
  const shown = new Set<string>();
  return teams.map((t) => {
    const members = byTeam.get(t)!;
    const counts = Object.fromEntries(PRIORITIES.map((p) => [p, members.reduce((n, g) => n + g.counts[p], 0)])) as Record<Priority, number>;
    const total = PRIORITIES.reduce((n, p) => n + counts[p], 0);
    return h(
      'section',
      { class: 'tier team', 'aria-labelledby': `team-${t}` },
      h('h2', { id: `team-${t}` }, `${TEAM[t].label} `, h('span', { class: 'count' }, `${total} ${total === 1 ? 'CVE' : 'CVEs'}`), tally(counts)),
      h('p', { class: 'muted small' }, TEAM[t].note),
      members.map((g) => renderComponent(g, shown)),
    );
  });
}

/** Results, with each family of similar CVEs folded under its highest-ranked member. */
function renderList(results: Result[]): HTMLElement {
  return h(
    'ol',
    { class: 'results' },
    foldFamilies(results).map(({ lead, related }) => {
      const li = renderResult(lead);
      if (related.length > 0) {
        li.append(
          h(
            'details',
            { class: 'related' },
            h('summary', { class: 'small' }, `+${related.length} similar ${related.length === 1 ? 'CVE' : 'CVEs'} in this product`),
            h('ol', { class: 'results' }, related.map(renderResult)),
          ),
        );
      }
      return li;
    }),
  );
}

/** How many change cards show before the rest fold away. */
const CHANGES_SHOWN = 8;

function renderChanges(feed: Feed): HTMLElement {
  const groups = groupChanges(feed.changes, feed.results);
  const section = h(
    'section',
    { class: 'block changes', 'aria-labelledby': 'changes-title' },
    // Always the last 7 days, whatever the results window, so the heading says so.
    h('h2', { id: 'changes-title' }, 'What changed in the last 7 days'),
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
    renderSummary(r?.summary ?? null),
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

let summaryCount = 0;

/** A CVE's summary, cut short with an Expand button when it's long. Always set as text, never HTML. */
function renderSummary(text: string | null): HTMLElement | null {
  const short = shortSummary(text);
  const full = fullSummary(text);
  if (!short || !full) return null;
  if (short === full) return h('p', { class: 'small summary' }, full);
  const body = h('span', { id: `summary-${++summaryCount}` }, short);
  const toggle = h('button', { type: 'button', class: 'link expand', 'aria-expanded': 'false', 'aria-controls': body.id }, 'Expand');
  toggle.addEventListener('click', () => {
    const open = toggle.getAttribute('aria-expanded') !== 'true';
    body.textContent = open ? full : short;
    toggle.setAttribute('aria-expanded', String(open));
    toggle.textContent = open ? 'Collapse' : 'Expand';
  });
  return h('p', { class: 'small summary' }, body, ' ', toggle);
}

/** From before the chosen window, kept in view because it's exploited, likely to be, or CVSS 9.9+. */
function olderBadge(r: Result): HTMLElement {
  const when = r.evidence.kevAddedAt ?? r.publishedAt;
  const month = when ? new Date(when).toLocaleDateString('en-GB', { month: 'short', year: 'numeric', timeZone: 'UTC' }) : null;
  // A listed CVE shows whatever its age: the date is only for reference.
  if (r.confidence === 'listed') {
    const published = r.publishedAt ? new Date(r.publishedAt).toLocaleDateString('en-GB', { month: 'short', year: 'numeric', timeZone: 'UTC' }) : null;
    return h('span', { class: 'badge older', title: 'You listed it, so it shows whatever its age.' }, published ? `Published ${published}` : 'Publication date unknown');
  }
  return h(
    'span',
    { class: 'badge older', title: 'Older than your time window. Exploited, likely to be, or CVSS 9.9+ CVEs from the last year always show, in case they were missed.' },
    month ? `Older: ${r.evidence.kevAddedAt ? 'on KEV since' : 'from'} ${month}` : 'Older than your window',
  );
}

/** How it matched: a listed CVE says so in place of exact or close, and names any duplicates it replaces. */
function matchBadges(r: Result): HTMLElement[] {
  const replaces = r.replaces?.length
    ? [h('span', { class: 'badge replaces', title: 'Rejected as a duplicate of this CVE, so this one ranks in its place' }, `Replaces ${r.replaces.join(', ')}`)]
    : [];
  if (r.confidence === 'listed') return [h('span', { class: 'badge match-exact' }, r.matched.length > 0 ? 'From your list' : 'In place of a duplicate'), ...replaces];
  return [
    h('span', { class: `badge match-${r.match}` }, r.match === 'exact' ? 'Exact match' : 'Close match'),
    h('span', { class: `badge ${r.confidence}` }, r.confidence === 'version_confirmed' ? 'Version confirmed' : 'Version not confirmed'),
    ...replaces,
  ];
}

/** The stack items it matched; listed CVEs are left out, since the ID above already says it. */
function matchedLine(r: Result): HTMLElement | null {
  const items = r.matched.filter((m) => !m.startsWith('cve:'));
  if (items.length === 0) return null;
  return h('p', { class: 'small' }, 'Matched ', items.flatMap((m, i) => [i > 0 ? ', ' : '', h('code', {}, itemMarks(m).name)]), r.matched.length > items.length ? ' and your list' : '');
}

function renderResult(r: Result): HTMLElement {
  const advisory = safeHref(r.links.advisory);
  const patch = safeHref(r.links.patch);
  const mitigationLink = safeHref(r.mitigation?.advisory);
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
      r.respondWithinHours !== null
        ? h(
            'span',
            { class: 'badge respond', title: 'Guidance, not a deadline: exploits for urgent bugs now often appear within hours of disclosure' },
            `Respond within ${describeHours(r.respondWithinHours)}`,
          )
        : null,
      h('h3', {}, advisory ? h('a', { href: advisory, rel: 'noreferrer noopener', target: '_blank' }, r.id) : r.id),
      r.beforeWindow ? olderBadge(r) : null,
    ),
    r.title ? h('p', { class: 'title' }, r.title) : null,
    renderSummary(r.summary),
    renderWhy(r),
    // The same steps as the export, so the page and a file handed to an assistant say the same thing.
    h('p', { class: `todo small${r.mitigation && r.fixedVersions.length === 0 ? ' mitigate' : ''}` }, h('strong', {}, 'What to do: '), remediationSteps(r).join(' ')),
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
      e.lev !== null && e.lev >= 0.01
        ? h(
            'span',
            { class: 'badge', title: 'NIST LEV: estimated chance it has already been exploited, from its EPSS history. A lower bound, not evidence.' },
            `LEV ${pct(e.lev)}`,
          )
        : null,
      e.knownRansomware ? h('span', { class: 'badge ransomware' }, 'Used in ransomware') : null,
      ...matchBadges(r),
    ),
    e.kevAddedAt
      ? h('p', { class: 'evidence' }, `On CISA KEV since ${e.kevAddedAt.slice(0, 10)}${e.kevDueDate ? `, federal due date ${e.kevDueDate.slice(0, 10)}` : ''}`)
      : null,
    matchedLine(r),
    h(
      'p',
      { class: 'small links' },
      advisory ? h('a', { href: advisory, rel: 'noreferrer noopener', target: '_blank' }, 'Advisory') : null,
      patch ? h('a', { href: patch, rel: 'noreferrer noopener', target: '_blank' }, 'Patch') : null,
      mitigationLink && mitigationLink !== advisory ? h('a', { href: mitigationLink, rel: 'noreferrer noopener', target: '_blank' }, 'Mitigation guidance') : null,
    ),
  );
}

/** Why: the signal that decided the band first, then the rest, then what the band couldn't use. */
function renderWhy(r: Result): HTMLElement | null {
  const { decisive, others, missing } = r.why;
  if (!decisive && others.length === 0 && missing.length === 0) return null;
  return h(
    'div',
    { class: 'why small' },
    decisive || others.length > 0
      ? h(
          'p',
          {},
          h('strong', {}, 'Why: '),
          decisive ? h('span', { class: `decisive ${decisive.kind}`, title: `Decided the priority (${KIND_LABEL[decisive.kind]})` }, decisive.text) : null,
          ...others.flatMap((o, i) => [i > 0 || decisive ? '; ' : '', h('span', { title: KIND_LABEL[o.kind] }, o.text)]),
        )
      : null,
    missing.length > 0 ? h('p', { class: 'muted' }, 'Not available: ', missing.join('; ')) : null,
  );
}

const KIND_LABEL: Record<Reason['kind'], string> = {
  evidence: 'evidence of exploitation',
  prediction: 'a prediction',
  severity: 'severity',
  context: 'reachability and context',
};

function copyButtons(feed: Feed): HTMLElement {
  const badgeMd = `[![known-exploited CVEs](${feed.links.badge})](${feed.links.page})`;
  const items: [string, string][] = [
    ['Copy page link', feed.links.page],
    ['Copy Atom link', feed.links.atom],
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

/** Saves the results as Markdown for an AI agent, built here from the feed already loaded. */
function exportButtons(feed: Feed): HTMLElement {
  const save = async () => {
    const file = exportFileName(feed);
    // The record names how fresh each source was; without the answer it says so.
    const sources = await getHealth().then(
      (h) => h.sources,
      () => null,
    );
    const url = URL.createObjectURL(new Blob([exportMarkdown(feed, config?.displayName ?? 'Vulnder', sources)], { type: 'text/markdown;charset=utf-8' }));
    const a = h('a', { href: url, download: file });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    say(`Saved ${file}.`);
  };
  const title =
    'Downloads a Markdown file listing every CVE here with its priority, why and how to fix it, written for an AI coding agent (or a person) to work through and apply the fixes';
  return h('div', { class: 'copy' }, h('button', { type: 'button', title, onclick: save }, 'Export for AI'));
}

// ---------- Footer ----------

/** Fills in the footer's checks served and each source's age; the source links are static. */
async function renderFooter(): Promise<void> {
  let health: Awaited<ReturnType<typeof getHealth>>;
  try {
    health = await getHealth();
  } catch {
    return; // the links still stand without ages
  }
  const checks = checksServedText(health.checksServed);
  const checksEl = document.getElementById('checks');
  if (checksEl && checks) {
    checksEl.textContent = checks;
    checksEl.hidden = false;
  }
  const names: string[] = [];
  for (const el of document.querySelectorAll<HTMLElement>('[data-source]')) {
    const s = health.sources[el.dataset.source ?? ''];
    if (!s) continue;
    names.push(el.dataset.source!);
    el.textContent = sourceAge(s);
    el.classList.toggle('stale', s.health !== 'ok');
  }
  const status = sourcesStatus(health.sources, names);
  const statusEl = document.getElementById('sources-status');
  if (statusEl && status) {
    statusEl.textContent = status.text;
    statusEl.classList.toggle('stale', status.behind > 0);
  }
}

const canonical = document.querySelector('link[rel="canonical"]');
const noindex = h('meta', { name: 'robots', content: 'noindex' });

/**
 * Keeps stack links out of search results; crawlers see this after rendering.
 * A canonical pointing at the home page would contradict noindex, so it goes
 * while a stack is shown and comes back with the home page.
 */
function markIndexable(): void {
  if (indexable(location.search)) {
    noindex.remove();
    if (canonical && !canonical.isConnected) document.head.append(canonical);
  } else {
    canonical?.remove();
    document.head.append(noindex);
  }
}

/** Counts routes, so one still waiting when a newer one starts (Back, then a quick submit) draws nothing over it. */
let routes = 0;

async function route(): Promise<void> {
  const at = ++routes;
  markIndexable();
  const params = new URLSearchParams(location.search);
  const s = params.get('s');
  if (s) await renderResults(s, Number(params.get('days') ?? 30) || 30);
  else {
    await refreshPass();
    if (at !== routes) return;
    renderInput();
  }
  app.focus();
}

window.addEventListener('popstate', () => void route());

config = await getConfig().catch(() => null);
if (config) document.querySelectorAll('[data-name]').forEach((n) => (n.textContent = config!.displayName));
await route();
void renderFooter();
