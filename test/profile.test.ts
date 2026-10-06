import { describe, expect, it } from 'vitest';
import type { Chip } from '../src/resolve/catalog';
import { canRank, NO_PROFILE, orderByFit, parseProfile, rankableChips, type StackProfile } from '../src/resolve/profile';

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
