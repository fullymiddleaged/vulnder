import { describe, expect, it } from 'vitest';
import type { Chip } from '../src/resolve/catalog';
import { canRank, isEnterprise, markTeams, MIN_RANK_CONFIDENCE, NO_PROFILE, orderByFit, parseProfile, rankableChips, type StackProfile } from '../src/resolve/profile';

const close = (item: string) => ({ item, label: item, close: true, known: true });
const exact = (item: string) => ({ item, label: item, close: false, known: true });

const SWITCHES: Chip = { input: 'Cisco switches', status: 'resolved', items: ['?p:cisco/ios_xe', '?p:cisco/nx_os', '?p:cisco/small_business_switches'].map(close) };
const NGINX: Chip = { input: 'nginx', status: 'resolved', items: ['?p:f5/nginx', '?p:nginx/nginx'].map(close) };
const POSTGRES: Chip = { input: 'Postgres', status: 'resolved', items: [exact('p:postgresql/postgresql')] };
const ONE_CLOSE: Chip = { input: 'Grafanna', status: 'resolved', items: [close('?p:grafana/grafana')] };

const home: StackProfile = { scale: { value: 'home', confidence: 0.9 }, hosting: { value: null, confidence: 0 } };

describe('canRank', () => {
  it('needs one axis known with enough confidence', () => {
    expect(canRank(NO_PROFILE)).toBe(false);
    expect(canRank(home)).toBe(true);
    expect(canRank({ ...home, scale: { value: 'home', confidence: 0.49 } })).toBe(false);
    expect(canRank({ scale: { value: null, confidence: 0 }, hosting: { value: 'cloud', confidence: 0.5 } })).toBe(true);
  });
});

describe('rankableChips', () => {
  it('picks chips with several close matches and nothing exact', () => {
    expect(rankableChips([SWITCHES, POSTGRES, ONE_CLOSE, NGINX])).toEqual([SWITCHES, NGINX]);
  });
});

describe('orderByFit', () => {
  it('puts the best fit first, leaves other chips alone and never drops an item', () => {
    const fit = new Map([
      ['?p:cisco/ios_xe', 0.1],
      ['?p:cisco/small_business_switches', 0.9],
      ['?p:cisco/nx_os', 0.2],
      ['p:postgresql/postgresql', 0],
    ]);
    const [switches, postgres] = orderByFit([SWITCHES, POSTGRES], fit);
    expect(switches!.items.map((i) => i.item)).toEqual(['?p:cisco/small_business_switches', '?p:cisco/nx_os', '?p:cisco/ios_xe']);
    expect(postgres).toBe(POSTGRES);
    // The input is not mutated.
    expect(SWITCHES.items[0]!.item).toBe('?p:cisco/ios_xe');
  });

  it('treats unjudged items as neutral and keeps catalog order for ties', () => {
    const [switches] = orderByFit([SWITCHES], new Map([['?p:cisco/small_business_switches', 0.6]]));
    expect(switches!.items.map((i) => i.item)).toEqual(['?p:cisco/small_business_switches', '?p:cisco/ios_xe', '?p:cisco/nx_os']);
    expect(orderByFit([SWITCHES], new Map())[0]!.items).toEqual(SWITCHES.items);
  });
});

describe('parseProfile', () => {
  it('reads a stored profile and rejects anything malformed', () => {
    expect(parseProfile(home)).toEqual(home);
    expect(parseProfile({ scale: { value: 'mars', confidence: 1 }, hosting: { value: null, confidence: 0 } })).toEqual(NO_PROFILE);
    expect(parseProfile({ scale: { value: 'home', confidence: 2 }, hosting: { value: null, confidence: 0 } })).toEqual(NO_PROFILE);
    expect(parseProfile(undefined)).toEqual(NO_PROFILE);
    expect(parseProfile('home')).toEqual(NO_PROFILE);
  });
});

describe('isEnterprise', () => {
  it('needs enterprise scale with enough confidence', () => {
    const at = (value: StackProfile['scale']['value'], confidence: number) => isEnterprise({ ...NO_PROFILE, scale: { value, confidence } });
    expect(at('enterprise', MIN_RANK_CONFIDENCE)).toBe(true);
    expect(at('enterprise', MIN_RANK_CONFIDENCE - 0.01)).toBe(false);
    expect(at('smb', 0.99)).toBe(false);
    expect(at('home', 0.99)).toBe(false);
    expect(isEnterprise(NO_PROFILE)).toBe(false);
  });
});

describe('markTeams', () => {
  const items = (chips: Chip[]) => chips.map((c) => c.items.map((i) => [i.item, i.team ?? null]));
  const OBSCURE: Chip = { input: 'Frobnicator', status: 'resolved', items: [exact('p:someone/frobnicator')] };

  it("gives every item of a chip Jev's team, ahead of the table's guess", () => {
    const marked = markTeams([NGINX, POSTGRES], new Map([['nginx', 'network']]));
    expect(items(marked)).toEqual([
      [
        ['?p:f5/nginx;network', 'network'],
        ['?p:nginx/nginx;network', 'network'],
      ],
      [['p:postgresql/postgresql;database', 'database']],
    ]);
  });

  it("fills what Jev left out from the table, and leaves an item it doesn't know without a team", () => {
    const marked = markTeams([SWITCHES, OBSCURE], new Map());
    expect(marked[0]!.items.every((i) => i.team === 'network')).toBe(true);
    expect(marked[1]).toBe(OBSCURE);
    const judged = markTeams([OBSCURE], new Map([['Frobnicator', 'business']]));
    expect(items(judged)).toEqual([[['p:someone/frobnicator;business', 'business']]]);
  });

  it('keeps other marks and never adds, drops or reorders items', () => {
    const marked = markTeams([SWITCHES, { input: 'edge', status: 'resolved', items: [close('?p:f5/nginx@1.27')] }], new Map([['edge', 'platform']]));
    expect(marked[0]!.items.map((i) => i.label)).toEqual(SWITCHES.items.map((i) => i.label));
    expect(marked[1]!.items[0]!.item).toBe('?p:f5/nginx@1.27;platform');
  });
});
