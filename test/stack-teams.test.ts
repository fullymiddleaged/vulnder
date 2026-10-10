import { describe, expect, it } from 'vitest';
import { parseStack, type Team } from '../src/stack/format';
import { guessTeam, isEdge, isEdgeDevice } from '../src/stack/teams';
import { TEAM, TEAM_GROUPS, teamOf } from '../web/teams';

const guess = (item: string) => guessTeam(parseStack(item)[0]!);

describe('guessTeam', () => {
  it.each<[string, Team | null]>([
    ['npm:react@18.2.0', 'frontend'],
    ['npm:@angular/core', 'frontend'],
    ['npm:vue-router', 'frontend'],
    ['npm:express', 'backend'],
    ['npm:reactive-db', 'backend'],
    ['pypi:django', 'backend'],
    ['maven:org.apache.logging.log4j:log4j-core@2.17.1', 'backend'],
    ['actions:actions/checkout', 'platform'],
    ['p:postgresql/postgresql@16', 'database'],
    ['p:mongodb/mongodb_server', 'database'],
    ['p:microsoft/sql_server', 'database'],
    ['p:cisco/ios_xe', 'network'],
    ['p:cisco/catalyst_9300', 'network'],
    ['p:fortinet/fortios', 'network'],
    ['p:fortinet/fortimail', 'network'],
    ['p:paloaltonetworks/pan_os', 'network'],
    ['p:mikrotik/routeros', 'network'],
    ['p:netscaler/adc', 'network'],
    ['p:citrix_netscaler/gateway', 'network'],
    ['p:tp_link_systems_inc/archer_ax21', 'network'],
    // Vendors CVE records spell their own way: found through the vendor's family.
    ['p:juniper_networks/junos_os', 'network'],
    ['p:arista_networks/eos', 'network'],
    ['p:hewlett_packard_enterprise_hpe/aos_cx', 'network'],
    ['p:check_point/security_gateway', 'network'],
    ['p:cisco/webex_meetings', 'endpoints'],
    ['p:f5/nginx', 'platform'],
    ['p:apache/http_server', 'platform'],
    ['p:linux/linux_kernel', 'platform'],
    ['p:microsoft/windows_server_2022', 'platform'],
    ['p:microsoft/windows_11_23h2', 'endpoints'],
    ['p:google/chrome', 'endpoints'],
    ['p:apple/macos', 'endpoints'],
    ['p:microsoft/exchange_server', 'business'],
    ['p:atlassian/jira_server', 'business'],
    ['p:atlassian/bamboo', 'platform'],
    ['p:wordpress/wordpress', 'business'],
    ['p:vmware/vcenter_server', 'platform'],
    ['p:someone/obscure_plugin', null],
  ])('%s is %s', (item, team) => {
    expect(guess(item)).toBe(team);
  });

  it('ignores marks, and is safe on prototype keys', () => {
    for (const item of ['p:cisco/ios_xe', 'npm:react', 'p:postgresql/postgresql']) {
      expect(guess(`?${item};business`)).toBe(guess(item));
    }
    expect(guess('p:__proto__/constructor')).toBeNull();
    expect(guess('p:constructor/tostring')).toBeNull();
  });
});

describe('isEdge', () => {
  const edge = (item: string) => isEdge(parseStack(item)[0]!);

  it("takes the user's tag over what the product is, both ways", () => {
    expect(edge('p:fortinet/fortios')).toBe(true);
    expect(edge('p:fortinet/fortios;internal')).toBe(false);
    expect(edge('p:acme/customer_portal')).toBe(false);
    expect(edge('p:acme/customer_portal;edge')).toBe(true);
    expect(edge('p:acme/customer_portal;business;edge')).toBe(true);
    expect(edge('npm:express')).toBe(false);
  });
});

describe('isEdgeDevice', () => {
  const edge = (item: string) => isEdgeDevice(parseStack(item)[0]!);

  it('knows VPNs, edge firewalls, gateways and ADCs, however the vendor is spelled', () => {
    for (const item of [
      'p:fortinet/fortios@7.4',
      'p:fortinet/fortinet_fortios',
      'p:paloaltonetworks/pan_os',
      'p:palo_alto_networks/pan_os',
      'p:netscaler/adc',
      'p:citrix_netscaler/gateway',
      'p:f5/big_ip',
      'p:ivanti/connect_secure',
      'p:cisco/cisco_secure_firewall_adaptive_security_appliance_asa_software',
      'p:sonicwall/sonicos',
      '?p:checkpoint/quantum_security_gateway;network',
      // Misses found against the catalog: SSL VPNs, edge routers, mail gateways, WAFs, SMB gateways, remote support.
      'p:sonicwall/sma1000',
      'p:mikrotik/routeros',
      'p:cisco/secure_email_gateway',
      'p:progress_software/moveit_waf',
      'p:palo_alto_networks/cloud_ngfw',
      'p:ubiquiti_inc/unifi_gateways',
      'p:hewlett_packard_enterprise_hpe/edgeconnect_sd_wan_gateways',
      'p:vmware/avi_load_balancer',
      'p:okta/okta_access_gateway',
      'p:connectwise/screenconnect',
      'p:juniper_networks/junos_os',
      'p:check_point/security_gateway',
    ]) {
      expect(edge(item), item).toBe(true);
    }
  });

  it('leaves out consoles, clients, inside gear, packages and unknown vendors', () => {
    for (const item of [
      'p:fortinet/fortimanager',
      'p:cisco/cisco_secure_firewall_management_center_fmc',
      'p:ivanti/connect_secure_client',
      'p:cisco/anyconnect_secure_mobility_client',
      'p:palo_alto_networks/globalprotect',
      'p:cisco/ios_xe',
      'p:f5/nginx',
      // Near misses found against the catalog: a browser named Edge, a router library, a firewall log tool.
      'p:microsoft/microsoft_edge_chromium_based',
      'p:remix_run/react_router',
      'p:zohocorp/manageengine_firewall_analyzer',
      'p:postgresql/postgresql',
      'npm:fortios',
      'p:__proto__/constructor',
      'p:constructor/tostring',
      'p:hasownproperty/valueof',
    ]) {
      expect(edge(item), item).toBe(false);
    }
  });
});

describe('teamOf', () => {
  it('reads the team an item carries, or Unassigned', () => {
    expect(teamOf('?p:cisco/ios_xe@17.9;network')).toBe('network');
    expect(teamOf('p:cisco/ios_xe')).toBe('unassigned');
    expect(teamOf('p:cisco/ios_xe;nonsense')).toBe('unassigned');
  });

  it('labels every group, Unassigned last', () => {
    for (const t of TEAM_GROUPS) expect(TEAM[t].label).toBeTruthy();
    expect(TEAM_GROUPS.at(-1)).toBe('unassigned');
  });
});
