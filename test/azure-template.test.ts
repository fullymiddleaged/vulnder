import { describe, expect, it } from 'vitest';
import bicep from '../integrations/azure/main.bicep?raw';
import workflowText from '../integrations/azure/workflow.json?raw';
import newAct from '../integrations/azure/kql/new-act.kql?raw';
import latest from '../integrations/azure/kql/latest.kql?raw';
import defenderDevices from '../integrations/azure/kql/defender-devices.kql?raw';
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

  it('uses only declared parameters and initialised variables, and main.bicep passes every parameter', () => {
    const declared = Object.keys(workflow.parameters);
    for (const p of refs('parameters')) expect(declared).toContain(p);
    const initialised = all.flatMap((s) =>
      Object.values(s.actions).flatMap((a) => (a.type === 'InitializeVariable' ? ((a.inputs as { variables: { name: string }[] }).variables.map((v) => v.name)) : [])),
    );
    for (const v of refs('variables')) expect(initialised).toContain(v);
    const passed = /definition: loadJsonContent\('workflow\.json'\)\s*parameters: \{.*?\n {4}\}/s.exec(bicep)?.[0] ?? '';
    for (const p of declared) expect(passed, `main.bicep passes ${p}`).toMatch(new RegExp(`\\b${p}: \\{ value: `));
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
  const stream = /streamDeclarations: \{.*?columns: \[(.*?)\]/s.exec(bicep)?.[1] ?? '';
  const declared = [...stream.matchAll(/name: '([^']+)'/g)].map((m) => m[1]!);
  const table = /schema: \{.*?columns: \[(.*?)\]/s.exec(bicep)?.[1] ?? '';
  const columns = [...table.matchAll(/name: '([^']+)'/g)].map((m) => m[1]!);
  const transform = /transformKql: '(.*)'/.exec(bicep)?.[1] ?? '';

  it('declares every field a rank row has, plus what the workflow adds', () => {
    expect(declared.sort()).toEqual([...Object.keys(toRow(sample)), 'timeGenerated', 'runId', 'mode', 'source'].sort());
  });

  it('maps every declared field to a table column, and every column comes from the transform', () => {
    const projected = [...transform.matchAll(/(?:project |, )(\w+) = /g)].map((m) => m[1]!);
    expect(projected.sort()).toEqual([...columns].sort());
    for (const field of declared) expect(transform, field).toMatch(new RegExp(`(?:= |\\(|\\[\\\\')${field}\\b`));
  });

  it('never names a column Log Analytics reserves', () => {
    for (const reserved of ['id', 'Title', 'Type', 'TenantId', 'UniqueId', '_ResourceId', '_SubscriptionId']) expect(columns).not.toContain(reserved);
  });

  it("reads every deployment's latest run, not only the newest run in the table", () => {
    for (const [file, kql] of [['latest.kql', latest], ['defender-devices.kql', defenderDevices]]) {
      expect(kql, file).toMatch(/summarize arg_max\(TimeGenerated, RunId\) by Source/);
      expect(kql, file).toMatch(/RunId in \(latest\)/);
      expect(kql, file).toMatch(/summarize arg_max\(level\(Priority\) \* 1000 \+ Score, \*\).* by Cve/);
    }
  });

  it('alerts only from columns the table has', () => {
    const used = [...newAct.replace(/^\/\/.*$/gm, '').matchAll(/\b([A-Z][A-Za-z]+)\b/g)].map((m) => m[1]!).filter((w) => !['Vulnder_CL', 'FirstAct'].includes(w));
    for (const col of new Set(used)) expect(columns, col).toContain(col);
  });
});
