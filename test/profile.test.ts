import { describe, expect, it } from 'vitest';
import { isEdgeProduct, type Chip } from '../src/resolve/catalog';
import { canRank, EXPOSED_AT, markExposed, NO_PROFILE, orderByFit, parseProfile, rankableChips, type StackProfile } from '../src/resolve/profile';
import { parseStack } from '../src/stack/format';

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

describe('markExposed', () => {
  const items = (chips: Chip[]) => chips.map((c) => c.items.map((i) => [i.item, i.exposed ?? false]));

  it('marks every item of a chip Jev judged internet-facing, from the threshold up', () => {
    const marked = markExposed([NGINX, POSTGRES], new Map([['nginx', EXPOSED_AT], ['Postgres', EXPOSED_AT - 0.01]]));
    expect(items(marked)).toEqual([
      [
        ['!?p:f5/nginx', true],
        ['!?p:nginx/nginx', true],
      ],
      [['p:postgresql/postgresql', false]],
    ]);
  });

  it('leaves chips alone without an answer, and never adds, drops or reorders items', () => {
    expect(markExposed([SWITCHES, POSTGRES], new Map())).toEqual([SWITCHES, POSTGRES]);
    const marked = markExposed([SWITCHES], new Map([['Cisco switches', 0.99]]));
    expect(marked[0]!.items.map((i) => i.label)).toEqual(SWITCHES.items.map((i) => i.label));
  });

  it('keeps a mark already on an item', () => {
    const already: Chip = { input: 'edge', status: 'resolved', items: [{ ...exact('!p:f5/nginx'), exposed: true }] };
    expect(items(markExposed([already], new Map([['edge', 0.9]])))).toEqual([[['!p:f5/nginx', true]]]);
  });
});

describe('isEdgeProduct', () => {
  const edge = (item: string) => isEdgeProduct(parseStack(item)[0]!);

  it('knows gateways, edge firewalls and ADCs by their catalog keys', () => {
    for (const item of [
      'p:fortinet/fortios@7.4',
      'p:fortinet/fortiproxy',
      'p:cisco/cisco_secure_firewall_adaptive_security_appliance_asa_software',
      'p:cisco/cisco_secure_firewall_threat_defense_ftd_software',
      'p:palo_alto_networks/pan_os',
      'p:ivanti/connect_secure',
      'p:citrix/netscaler_adc_and_netscaler_gateway',
      'p:f5/big_ip',
      'p:sonicwall/sma1000',
      'p:watchguard/fireware_os',
      'p:zyxel/usg_flex_series_firmware',
      'p:openvpn/access_server',
      // A repeated vendor prefix is stripped before anchored patterns are tested.
      'p:fortinet/fortinet_fortios',
    ]) {
      expect(edge(item), item).toBe(true);
    }
  });

  it('leaves out their consoles and clients, inside gear, packages and unknown vendors', () => {
    for (const item of [
      'p:cisco/cisco_secure_firewall_management_center_fmc',
      'p:checkpoint/quantum_security_management',
      'p:palo_alto_networks/globalprotect_app',
      'p:palo_alto_networks/prisma_access_agent',
      'p:f5/big_ip_next_central_manager',
      'p:ivanti/connect_secure_client',
      'p:cisco/ios_xe',
      'p:f5/nginx',
      'p:postgresql/postgresql',
      'npm:fortios',
      'p:__proto__/fortios',
      'p:constructor/pan_os',
    ]) {
      expect(edge(item), item).toBe(false);
    }
  });
});

describe('markExposed: edge products', () => {
  it('marks edge products without Jev, and only those among close matches', () => {
    const cisco: Chip = { input: 'Cisco gear', status: 'resolved', items: ['?p:cisco/ios_xe', '?p:cisco/cisco_secure_firewall_adaptive_security_appliance_asa_software'].map(close) };
    const marked = markExposed([cisco, POSTGRES], new Map());
    expect(marked[0]!.items.map((i) => i.item)).toEqual(['?p:cisco/ios_xe', '!?p:cisco/cisco_secure_firewall_adaptive_security_appliance_asa_software']);
    expect(marked[1]).toBe(POSTGRES);
  });

  it('marks an edge product even when Jev says the text does not', () => {
    const forti: Chip = { input: 'FortiGate VPN', status: 'resolved', items: [exact('p:fortinet/fortios')] };
    expect(markExposed([forti], new Map([['FortiGate VPN', 0.1]]))[0]!.items[0]!.item).toBe('!p:fortinet/fortios');
  });
});
