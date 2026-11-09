import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { app } from '../src/index';
import { parseStack, serializeStack } from '../src/stack/format';
import { azureDeployUrl } from '../web/format';
import bicep from '../integrations/azure/main.bicep?raw';
import workspaceBicep from '../integrations/azure/workspace.bicep?raw';
import logicAppBicep from '../integrations/azure/logicapp.bicep?raw';
import workflowText from '../integrations/azure/workflow.json?raw';
import newAct from '../integrations/azure/kql/new-act.kql?raw';
import latest from '../integrations/azure/kql/latest.kql?raw';
import defenderDevices from '../integrations/azure/kql/defender-devices.kql?raw';
import dailyPatchList from '../integrations/azure/kql/daily-patch-list.kql?raw';
import armText from '../integrations/azure/azuredeploy.json?raw';
import uiText from '../integrations/azure/createUiDefinition.json?raw';
import azureDoc from '../docs/AZURE.md?raw';
import readme from '../README.md?raw';
import home from '../public/index.html?raw';
import howItWorks from '../public/how-it-works.html?raw';
import type { MatchedVuln } from '../src/match/match';
import { toRow } from '../src/routes/api';

/**
 * The Azure template can't be deployed from CI, so this checks what can be
 * checked offline: the workflow's references resolve, its parameters are
 * passed, and the data collection rule declares every field /api/v1/rank
 * returns, so a new row field can't be dropped without someone noticing.
 */

type Json = Record<string, unknown>;
const workflow = JSON.parse(workflowText) as { parameters: Json; actions: Json };

interface Scope {
  actions: Record<string, Json>;
}

/** Every action, with the action scopes (a Foreach's, a Switch case's, an If's else) it sits in. */
function scopes(actions: Record<string, Json>, out: Scope[] = []): Scope[] {
  out.push({ actions });
  for (const a of Object.values(actions)) {
    if (a.actions) scopes(a.actions as Record<string, Json>, out);
    for (const c of Object.values((a.cases as Record<string, Json>) ?? {})) scopes(c.actions as Record<string, Json>, out);
    if (a.default) scopes((a.default as Json).actions as Record<string, Json>, out);
    if (a.else) scopes((a.else as Json).actions as Record<string, Json>, out);
  }
  return out;
}

const all = scopes(workflow.actions as Record<string, Json>);
const names = new Set(all.flatMap((s) => Object.keys(s.actions)));
const refs = (fn: string) => [...workflowText.matchAll(new RegExp(`${fn}\\('([^']+)'\\)`, 'g'))].map((m) => m[1]!);

describe('Azure workflow', () => {
  it('refers only to actions that exist', () => {
    for (const fn of ['body', 'outputs', 'items', 'actions']) for (const name of refs(fn)) expect(names, `${fn}('${name}')`).toContain(name);
  });

  it('runs each action after one in its own scope', () => {
    for (const scope of all) {
      for (const [name, a] of Object.entries(scope.actions)) {
        for (const after of Object.keys((a.runAfter as Json) ?? {})) expect(Object.keys(scope.actions), `${name} runs after ${after}`).toContain(after);
      }
    }
  });

  it('uses only declared parameters and initialised variables, and logicapp.bicep passes every parameter', () => {
    const declared = Object.keys(workflow.parameters);
    for (const p of refs('parameters')) expect(declared).toContain(p);
    const initialised = all.flatMap((s) =>
      Object.values(s.actions).flatMap((a) => (a.type === 'InitializeVariable' ? ((a.inputs as { variables: { name: string }[] }).variables.map((v) => v.name)) : [])),
    );
    for (const v of refs('variables')) expect(initialised).toContain(v);
    const passed = /definition: loadJsonContent\('workflow\.json'\)\s*parameters: \{.*?\n {4}\}/s.exec(logicAppBicep)?.[0] ?? '';
    for (const p of declared) expect(passed, `logicapp.bicep passes ${p}`).toMatch(new RegExp(`\\b${p}: \\{ value: `));
  });

  it('ranks the stack after any mode, adding to its rows, and fails mode stack without one', () => {
    const actions = workflow.actions as Record<string, Json>;
    const ifStack = actions.If_stack as { runAfter: Json; actions: Record<string, Json> };
    expect(Object.keys(ifStack.runAfter)).toEqual(['Switch_on_mode']);
    expect(Object.keys((actions.Tag_rows as { runAfter: Json }).runAfter)).toEqual(['If_stack']);
    expect(JSON.stringify(ifStack.actions.Rank_stack)).toContain("parameters('stack')");
    expect(ifStack.actions.Merge_stack_rows!.inputs).toBe("@union(variables('rows'), body('Rank_stack')?['rows'])");
    const stackCase = (actions.Switch_on_mode as { cases: Record<string, { case: string; actions: Json }> }).cases.Stack!;
    expect(JSON.stringify(stackCase.actions)).toContain('"runStatus":"Failed"');
  });

  it('has a case for every mode main.bicep allows', () => {
    const allowed = [...(/@allowed\(\[([^\]]+)\]\)\s*param mode/.exec(bicep)?.[1] ?? '').matchAll(/'([^']+)'/g)].map((m) => m[1]);
    const cases = Object.values((workflow.actions.Switch_on_mode as { cases: Record<string, { case: string }> }).cases).map((c) => c.case);
    expect(cases.sort()).toEqual(allowed.sort());
  });
});

describe('Azure data collection rule', () => {
  const sample = {
    id: 'CVE-2026-1001',
    title: 't',
    priority: 'act',
    score: 90,
    respondWithinHours: 24,
    reasons: [],
    tier: 'exploited',
    evidence: { kevAddedAt: null, kevDueDate: null, knownRansomware: false, epss: null, epssPercentile: null, epssDate: null, lev: null },
    ssvc: null,
    cvss: null,
    publishedAt: null,
    beforeWindow: false,
    matched: [],
    match: 'exact',
    confidence: 'listed',
    fixedVersions: [],
    mitigation: null,
    links: { advisory: null, patch: null, exploit: null },
  } as unknown as MatchedVuln;
  const stream = /streamDeclarations: \{.*?columns: \[(.*?)\]/s.exec(logicAppBicep)?.[1] ?? '';
  const declared = [...stream.matchAll(/name: '([^']+)'/g)].map((m) => m[1]!);
  const table = /schema: \{.*?columns: \[(.*?)\]/s.exec(workspaceBicep)?.[1] ?? '';
  const columns = [...table.matchAll(/name: '([^']+)'/g)].map((m) => m[1]!);
  const transform = /transformKql: '(.*)'/.exec(logicAppBicep)?.[1] ?? '';

  it('declares every field a rank row has, plus what the workflow adds', () => {
    expect(declared.sort()).toEqual([...Object.keys(toRow(sample)), 'timeGenerated', 'runId', 'mode', 'sourceName'].sort());
  });

  it('brackets the field names the transform parser rejects bare', () => {
    // Azure refused `CveTitle = title` with "mismatched input ','" on a real deployment.
    for (const field of ['title', 'match']) {
      expect(transform, field).toContain(`= [\\'${field}\\']`);
      expect(transform, field).not.toMatch(new RegExp(`= ${field}\\b`));
    }
  });

  it("doesn't name a field source, the transform's input table", () => {
    expect(declared).not.toContain('source');
    expect(transform).not.toMatch(/\[\\'source\\'\]/);
  });

  it('maps every declared field to a table column, and every column comes from the transform', () => {
    const projected = [...transform.matchAll(/(?:project |, )(\w+) = /g)].map((m) => m[1]!);
    expect(projected.sort()).toEqual([...columns].sort());
    for (const field of declared) expect(transform, field).toMatch(new RegExp(`(?:= |\\(|\\[\\\\')${field}\\b`));
  });

  it('never names a column Log Analytics reserves', () => {
    for (const reserved of ['id', 'Title', 'Type', 'TenantId', 'UniqueId', '_ResourceId', '_SubscriptionId']) expect(columns).not.toContain(reserved);
  });

  it('names no let binding after a KQL keyword', () => {
    // Log Analytics refused `let latest = ...` ("Query could not be parsed at 'latest'") on a real workspace.
    const keywords = ['latest', 'title', 'source', 'match', 'project', 'summarize', 'where', 'extend', 'join', 'range', 'set', 'print'];
    const queries: [string, string][] = [['latest.kql', latest], ['defender-devices.kql', defenderDevices], ['new-act.kql', newAct], ['daily-patch-list.kql', dailyPatchList]];
    for (const [file, kql] of queries) {
      for (const [, name] of kql.matchAll(/^let (\w+)\s*=/gm)) expect(keywords, `${file}: let ${name}`).not.toContain(name);
    }
  });

  it("reads every deployment's latest run, not only the newest run in the table", () => {
    for (const [file, kql] of [['latest.kql', latest], ['defender-devices.kql', defenderDevices]]) {
      expect(kql, file).toMatch(/summarize arg_max\(TimeGenerated, RunId\) by Source/);
      expect(kql, file).toMatch(/RunId in \(latestRuns\)/);
      expect(kql, file).toMatch(/summarize arg_max\(level\(Priority\) \* 1000 \+ Score, \*\).* by Cve/);
    }
  });

  it('alerts only from columns the table has', () => {
    const used = [...newAct.replace(/^\/\/.*$/gm, '').matchAll(/\b([A-Z][A-Za-z]+)\b/g)].map((m) => m[1]!).filter((w) => !['Vulnder_CL', 'FirstAct', 'Ingested'].includes(w));
    for (const col of new Set(used)) expect(columns, col).toContain(col);
  });

  it('alerts by ingestion time, so a run that lands late still alerts once', () => {
    const query = newAct.replace(/^\/\/.*$/gm, '');
    expect(query).toMatch(/Ingested = ingestion_time\(\)/);
    expect(query).toMatch(/FirstAct = min\(Ingested\)/);
    expect(query).toMatch(/where FirstAct > ago\(1h\)/);
  });

  it("puts the CISA due date in the alert's details, from columns the query projects", () => {
    const details = /customDetails: \{([^}]*)\}/.exec(workspaceBicep)?.[1] ?? '';
    const columns = [...details.matchAll(/(\w+): '(\w+)'/g)].map((m) => m[2]!);
    expect(columns).toContain('KevDueDate');
    const projected = /\| project (.*)$/m.exec(newAct.replace(/^\/\/.*$/gm, ''))?.[1]?.split(/,\s*/) ?? [];
    for (const col of columns) expect(projected, col).toContain(col);
  });

  it('creates the analytics rule after the table its query reads', () => {
    const rule = /resource newActRule [\s\S]*?\n\}/.exec(workspaceBicep)?.[0] ?? '';
    expect(rule).toMatch(/dependsOn: \[table\]/);
  });

  it("creates the table and rule in the workspace's resource group, which can differ from the Logic App's", () => {
    expect(bicep).toMatch(/^param workspaceResourceGroup string = resourceGroup\(\)\.name$/m);
    const module = /module onWorkspace 'workspace\.bicep' = \{[\s\S]*?\n\}/.exec(bicep)?.[0] ?? '';
    expect(module).toContain('scope: resourceGroup(workspaceResourceGroup)');
    // The data collection rule writes to the module's workspace, so it waits for the table.
    expect(bicep).toContain('workspaceId: onWorkspace.outputs.workspaceId');
    expect(logicAppBicep).toContain('workspaceResourceId: workspaceId');
    expect(bicep, 'main.bicep only deploys the two modules').not.toMatch(/^resource /m);
  });
});

describe('Azure request sizes', () => {
  const actions = workflow.actions as Record<string, Json>;
  const json = (a: unknown) => JSON.stringify(a);

  it('sends Log Analytics at most 200 rows a call, inside its 1 MB limit', () => {
    const send = actions.If_any_rows as { actions: Record<string, { foreach: string }> };
    const size = Number(/chunk\(body\('Tag_rows'\), (\d+)\)/.exec(send.actions.For_each_200_rows!.foreach)?.[1]);
    // A rank row with long reasons, fixes and links is about 2 KB.
    expect(size * 2_000).toBeLessThan(1_000_000);
  });

  it("sends the Intune apps on most devices first, few enough for the API's 1 MB body", () => {
    const intune = (actions.Switch_on_mode as { cases: Record<string, { actions: Record<string, Json> }> }).cases.Intune!.actions;
    const from = (intune.Four_fields!.inputs as { from: string }).from;
    expect(from).toContain("reverse(sort(variables('apps'), 'deviceCount'))");
    const kept = Number(/, (\d+)\)$/.exec(from)?.[1]);
    // Four fields of a typical app entry come to about 150 bytes, 250 with long names.
    expect(kept * 250).toBeLessThanOrEqual(1_000_000);
  });

  it('tags rows with setProperty, which overwrites, not addProperty, which fails on a field the API already has', () => {
    const tag = json(actions.Tag_rows);
    expect(tag).not.toContain('addProperty');
    for (const field of ['timeGenerated', 'runId', 'mode', 'sourceName']) expect(tag).toContain(`'${field}'`);
  });
});

interface ArmParameter {
  type: string;
  defaultValue?: unknown;
  allowedValues?: string[];
  minValue?: number;
  maxValue?: number;
}

describe('Deploy to Azure', () => {
  // CI rebuilds azuredeploy.json with the Bicep CLI (npm run check:azure); these catch a stale build without it.
  const arm = JSON.parse(armText) as { parameters: Record<string, ArmParameter>; variables: Record<string, unknown>; resources: Json[] };
  const ui = JSON.parse(uiText) as {
    parameters: { basics: Json[]; steps: { name: string; elements: Json[] }[]; outputs: Record<string, string> };
  };
  const elements = [...ui.parameters.basics, ...ui.parameters.steps.flatMap((s) => s.elements)];
  const element = (name: string) => elements.find((e) => e.name === name)!;

  it('builds from the current main.bicep, workflow and query', () => {
    const params = [...bicep.matchAll(/^param (\w+) /gm)].map((m) => m[1]!);
    expect(Object.keys(arm.parameters).sort()).toEqual(params.sort());
    const nested = arm.resources.filter((r) => r.type === 'Microsoft.Resources/deployments') as { properties: { template: { variables: Record<string, unknown>; resources: Json[] } } }[];
    const variables = nested.flatMap((d) => Object.values(d.properties.template.variables));
    expect(variables, 'workflow.json').toContainEqual(workflow);
    expect(variables, 'new-act.kql').toContain(newAct);
    const dcr = nested.flatMap((d) => d.properties.template.resources).find((r) => r.type === 'Microsoft.Insights/dataCollectionRules') as { properties: { dataFlows: { transformKql: string }[] } };
    const transform = /transformKql: '(.*)'/.exec(logicAppBicep)?.[1]?.replaceAll("\\'", "'");
    expect(dcr.properties.dataFlows[0]!.transformKql).toBe(transform);
  });

  it("fills every parameter the template needs from the portal form, and only the template's parameters", () => {
    const outputs = Object.keys(ui.parameters.outputs);
    for (const o of outputs) expect(Object.keys(arm.parameters), o).toContain(o);
    for (const [name, p] of Object.entries(arm.parameters)) if (p.defaultValue === undefined) expect(outputs, name).toContain(name);
    for (const [param, value] of Object.entries(ui.parameters.outputs)) {
      const ref = /^\[(?:basics\('(\w+)'\)|steps\('\w+'\)\.(\w+))\]$/.exec(value);
      if (ref) expect(element(ref[1] ?? ref[2]!), param).toBeDefined();
    }
  });

  it("offers the template's modes, limits and defaults", () => {
    const modes = (element('mode').constraints as { allowedValues: { value: string; label: string }[] }).allowedValues;
    expect(modes.map((m) => m.value).sort()).toEqual([...arm.parameters.mode!.allowedValues!].sort());
    expect(modes.map((m) => m.label)).toContain(element('mode').defaultValue);
    const days = element('days');
    expect([days.min, days.max, days.defaultValue]).toEqual([arm.parameters.days!.minValue, arm.parameters.days!.maxValue, arm.parameters.days!.defaultValue]);
    for (const name of ['name', 'vulnderUrl']) {
      const e = element(name) as { defaultValue: string; constraints: { regex: string } };
      expect(e.defaultValue, name).toBe(arm.parameters[name]!.defaultValue);
      expect(e.defaultValue, name).toMatch(new RegExp(e.constraints.regex));
    }
  });

  it("picks the workspace with the portal's own resource picker, from any group in the subscription", () => {
    // An ArmApiControl listing workspaces, filtered to the chosen group, showed none in the portal.
    expect(elements.some((e) => e.type === 'Microsoft.Solutions.ArmApiControl')).toBe(false);
    const picker = element('workspace') as { type: string; resourceType: string; options: { filter: { subscription: string } } };
    expect(picker.type).toBe('Microsoft.Solutions.ResourceSelector');
    expect(picker.resourceType).toBe('Microsoft.OperationalInsights/workspaces');
    expect(picker.options.filter.subscription).toBe('onBasics');
  });

  it("reads the workspace from the picker's resource ID only, and warns until one is picked", () => {
    // The picker's name and location came through empty in the portal ("The name '/Vulnder_CL' ...").
    for (const [param, value] of Object.entries(ui.parameters.outputs)) expect(value, param).not.toMatch(/basics\('workspace'\)\.(name|location)/);
    expect(ui.parameters.outputs.workspaceName).toBe("[last(split(basics('workspace').id, '/'))]");
    const id = '/subscriptions/61cc0d6b/resourceGroups/vulnder-test/providers/Microsoft.OperationalInsights/workspaces/vulnder-test-ws';
    expect(id.split('/').at(-1)).toBe('vulnder-test-ws');
    expect(element('noWorkspace').visible).toBe("[empty(basics('workspace').id)]");
    // Log Analytics workspace names are 4 to 63 characters; an empty one fails clearly, not as '/Vulnder_CL'.
    expect(bicep).toMatch(/@minLength\(4\)\nparam workspaceName string/);
    expect((arm.parameters.workspaceName as ArmParameter & { minLength?: number }).minLength).toBe(4);
  });

  it("passes the workspace's resource group, read from its resource ID", () => {
    // '/subscriptions/{id}/resourceGroups/{group}/providers/...' split on '/' puts the group fifth.
    expect(ui.parameters.outputs.workspaceResourceGroup).toBe("[first(skip(split(basics('workspace').id, '/'), 4))]");
    const id = '/subscriptions/61cc0d6b/resourceGroups/vulnder-test/providers/Microsoft.OperationalInsights/workspaces/vulnder-test-ws';
    expect(id.split('/').slice(4)[0]).toBe('vulnder-test');
  });

  it("puts the Logic App and its rule in the workspace's region, which the template looks up itself", () => {
    // The portal's workspace picker passed an empty location, and Azure refused the deployment.
    expect(ui.parameters.outputs).not.toHaveProperty('location');
    expect(arm.parameters.location!.defaultValue).toBe('');
    expect(workspaceBicep).toMatch(/^output location string = workspace\.location$/m);
    expect(bicep).toContain('location: empty(location) ? onWorkspace.outputs.location : location');
    expect([...logicAppBicep.matchAll(/^ {2}location: (\w+)$/gm)].map((m) => m[1])).toEqual(['location', 'location']);
  });

  it('links the button on the home page, in the README and in AZURE.md to the committed template and form on main', () => {
    const raw = 'https://raw.githubusercontent.com/fullymiddleaged/vulnder/main/integrations/azure/';
    const expected = `https://portal.azure.com/#create/Microsoft.Template/uri/${encodeURIComponent(`${raw}azuredeploy.json`)}/createUIDefinitionUri/${encodeURIComponent(`${raw}createUiDefinition.json`)}`;
    for (const [file, text] of [['README.md', readme], ['docs/AZURE.md', azureDoc]]) expect(text, file).toContain(`(${expected})`);
    const pages: [string, string][] = [['index.html', home], ['how-it-works.html', howItWorks]];
    for (const [file, page] of pages) {
      const at = page.indexOf(`<a class="button" href="${expected}">`);
      expect(at, file).toBeGreaterThan(0);
      expect(page.slice(at, page.indexOf('</a>', at)), file).toMatch(/<\/svg>Deploy to Azure$/);
    }
  });

  it('links the home page row to the section on How it works', () => {
    expect(home).toContain('href="/how-it-works#sentinel"');
    expect(howItWorks).toContain('<h2 id="sentinel">');
  });
});

describe('Deploy to Azure from the results page', () => {
  type Served = { parameters: { basics: Json[]; steps: { elements: Json[] }[]; outputs: Record<string, unknown> } };
  const get = async (path: string) => {
    const res = await app.request(path, {}, env);
    return { res, body: (await res.json()) as Served };
  };
  const named = (form: Served, name: string) => [...form.parameters.basics, ...form.parameters.steps.flatMap((s) => s.elements)].find((e) => e.name === name);
  const STACK = 'p:fortinet/fortios@7.4.3;edge,p:paloaltonetworks/pan-os@11.1,npm:next@14.2.3,cve:2024-3400';

  it('builds a portal link to this deployment, with the stack in the form link', () => {
    const url = azureDeployUrl('https://vulnder.example', STACK, 30);
    const [, template, form] = /^https:\/\/portal\.azure\.com\/#create\/Microsoft\.Template\/uri\/([^/]+)\/createUIDefinitionUri\/([^/]+)$/.exec(url) ?? [];
    expect(decodeURIComponent(template!)).toBe('https://vulnder.example/azure/azuredeploy.json');
    const formUrl = new URL(decodeURIComponent(form!));
    expect(formUrl.origin + formUrl.pathname).toBe('https://vulnder.example/azure/createUiDefinition.json');
    expect(formUrl.searchParams.get('s')).toBe(STACK);
    expect(formUrl.searchParams.has('days')).toBe(false);
    expect(new URL(decodeURIComponent(/createUIDefinitionUri\/(.+)$/.exec(azureDeployUrl('https://vulnder.example', STACK, 7))![1]!)).searchParams.get('days')).toBe('7');
  });

  it('serves the template and the form with CORS, which the portal needs', async () => {
    for (const path of ['/azure/azuredeploy.json', '/azure/createUiDefinition.json', `/azure/createUiDefinition.json?s=${encodeURIComponent(STACK)}`]) {
      const res = await app.request(path, {}, env);
      expect(res.status, path).toBe(200);
      expect(res.headers.get('access-control-allow-origin'), path).toBe('*');
    }
    expect(await (await app.request('/azure/azuredeploy.json', {}, env)).json()).toEqual(JSON.parse(armText));
  });

  it('points the form at this deployment', async () => {
    const { body } = await get('/azure/createUiDefinition.json');
    expect(named(body, 'vulnderUrl')!.defaultValue).toBe(env.BASE_URL.replace(/\/+$/, ''));
    expect(named(body, 'stack')!.type).toBe('Microsoft.Common.TextBox');
  });

  it('fills in the stack, named in words, and passes it to the template as is', async () => {
    const { body } = await get(`/azure/createUiDefinition.json?s=${encodeURIComponent(STACK)}&days=14`);
    expect(named(body, 'stack')).toBeUndefined();
    const text = (named(body, 'stackSummary')!.options as { text: string }).text;
    expect(text).toContain('fortinet/fortios 7.4.3 (edge)');
    expect(text).toContain('paloaltonetworks/pan_os 11.1 (edge)'); // an edge device by what it is
    expect(text).toContain('npm next 14.2.3');
    expect(text).toContain('CVE-2024-3400');
    expect(text).not.toContain('p:');
    const canonical = serializeStack(parseStack(STACK));
    expect(body.parameters.outputs.stack).toBe(canonical);
    expect(canonical.startsWith('[')).toBe(false);
    expect(named(body, 'days')!.defaultValue).toBe(14);
    // Every output still names a template parameter.
    for (const o of Object.keys(body.parameters.outputs)) expect(Object.keys((JSON.parse(armText) as { parameters: object }).parameters), o).toContain(o);
  });

  it('names a long stack in part', async () => {
    const long = Array.from({ length: 60 }, (_, i) => `npm:pkg-${i}@1.0.0`).join(',');
    const { body } = await get(`/azure/createUiDefinition.json?s=${encodeURIComponent(long)}`);
    expect((named(body, 'stackSummary')!.options as { text: string }).text).toContain(', and 10 more.');
  });

  it('refuses a stack it cannot read', async () => {
    for (const s of ['', 'not a stack', '~!!!', '['.repeat(50), `p:a/b@${'9'.repeat(100)}`]) {
      const res = await app.request(`/azure/createUiDefinition.json?s=${encodeURIComponent(s)}`, {}, env);
      expect(res.status, s).toBe(400);
    }
    expect((await app.request(`/azure/createUiDefinition.json?s=${encodeURIComponent(STACK)}&days=500`, {}, env)).status).toBe(400);
  });
});
