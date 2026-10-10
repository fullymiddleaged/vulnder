import { normalizeKey } from '../lib/normalize';

/**
 * Product lines: what people call a product, mapped to every catalog key its
 * CVEs are filed under. CVE records use each vendor's own names, which rarely
 * match the short keys people (and NVD) use: Apache httpd is
 * `apache_software_foundation/apache_http_server`, RHEL is one product per
 * major version (`red_hat/red_hat_enterprise_linux_9`), Exchange one per
 * cumulative update. Fuzzy matching can't bridge that, and acronyms (RHEL,
 * SCCM, ADFS) share nothing with their keys at all, so these are curated.
 *
 * A key ending in `*` is a prefix: every catalog product starting with it, so
 * next year's `red_hat_enterprise_linux_11` joins without an edit. `keep`, when
 * set, is tested against what follows the prefix, leaving out add-ons that share
 * it. Check every key against the catalog before adding it (see
 * scripts/check-names.ts); the first plain key is used when the catalog has
 * nothing for the line yet, so the feed still watches it.
 */
export interface ProductLine {
  /** What people call it, as normalizeKey() output. */
  names: string[];
  keys: string[];
  keep?: RegExp;
  /** The release its names already say ("Windows 10" is release 10), used when no other version is given. */
  version?: string;
}

export const PRODUCT_LINES: ProductLine[] = [
  // Operating systems
  { names: ['windows', 'microsoft_windows'], keys: ['microsoft/windows', 'microsoft/windows_10_version_*', 'microsoft/windows_11_version_*'] },
  { names: ['windows_10', 'win10', 'win_10'], keys: ['microsoft/windows_10', 'microsoft/windows_10_version_*'], version: '10' },
  { names: ['windows_11', 'win11', 'win_11'], keys: ['microsoft/windows_11', 'microsoft/windows_11_version_*'], version: '11' },
  {
    // Active Directory, its certificate and federation roles, Hyper-V and IIS ship in Windows Server: Microsoft files their CVEs there.
    names: [
      'windows_server',
      'win_server',
      'microsoft_windows_server',
      'active_directory',
      'ad',
      'ad_ds',
      'adds',
      'ad_cs',
      'adcs',
      'domain_controller',
      'domain_controllers',
      'hyper_v',
      'wsus',
      'windows_server_update_services',
      'rdp',
      'remote_desktop_services',
    ],
    // The plain key stands for a release with nothing in the catalog ("Windows Server 2003").
    keys: ['microsoft/windows_server', 'microsoft/windows_server_*'],
    keep: /^\d{4}/,
  },
  { names: ['iis', 'microsoft_iis', 'internet_information_services'], keys: ['microsoft/internet_information_services', 'microsoft/windows_server_*'], keep: /^\d{4}/ },
  { names: ['adfs', 'ad_fs', 'active_directory_federation_services'], keys: ['microsoft/active_directory_federation_services', 'microsoft/windows_server_*'], keep: /^\d{4}/ },
  { names: ['rhel', 'red_hat_enterprise_linux', 'red_hat_linux', 'redhat_linux', 'redhat_enterprise_linux'], keys: ['redhat/enterprise_linux', 'red_hat/red_hat_enterprise_linux_*'], keep: /^\d+$/ },
  { names: ['sles', 'suse_linux_enterprise_server', 'suse_linux_enterprise', 'suse_enterprise_linux'], keys: ['suse/linux_enterprise_server', 'suse/suse_linux_enterprise_server_*'], keep: /^\d+(_sp\d+)?$/ },
  { names: ['centos', 'centos_linux', 'centos_stream'], keys: ['centos/centos'] },
  { names: ['oracle_linux'], keys: ['oracle/linux'] },
  { names: ['ios', 'apple_ios', 'iphone_os', 'ipados', 'apple_ipados'], keys: ['apple/iphone_os', 'apple/ipados', 'apple/ios_and_ipados'] },
  // Nothing in the catalog yet, and fuzzy matching finds unrelated products (Amazon Ion for Amazon Linux): better unmatched.
  { names: ['amazon_linux', 'amazon_linux_2', 'amazon_linux_2023', 'rocky_linux', 'rocky', 'almalinux', 'alma_linux', 'intune', 'microsoft_intune'], keys: [] },
  { names: ['openshift', 'ocp', 'openshift_container_platform', 'red_hat_openshift'], keys: ['redhat/openshift_container_platform', 'red_hat/red_hat_openshift_container_platform_*'], keep: /^\d+(_\d+)?$/ },

  // Microsoft servers and apps
  {
    names: ['exchange', 'exchange_server', 'microsoft_exchange', 'microsoft_exchange_server', 'owa', 'outlook_web_access', 'outlook_web_app'],
    keys: ['microsoft/exchange_server', 'microsoft/microsoft_exchange_server_*'],
  },
  { names: ['sql_server', 'mssql', 'ms_sql', 'ms_sql_server', 'microsoft_sql_server', 'sqlserver'], keys: ['microsoft/sql_server', 'microsoft/microsoft_sql_server_*'] },
  { names: ['sharepoint', 'sharepoint_server', 'microsoft_sharepoint'], keys: ['microsoft/sharepoint_server', 'microsoft/sharepoint', 'microsoft/sharepoint_*', 'microsoft/microsoft_sharepoint_*'] },
  {
    names: ['office', 'microsoft_office', 'office_365', 'o365', 'm365', 'microsoft_365', 'microsoft_365_apps', 'ms_office'],
    keys: ['microsoft/office', 'microsoft/365_apps', 'microsoft/microsoft_365_apps_*', 'microsoft/microsoft_office_*'],
  },
  {
    names: ['entra', 'entra_id', 'microsoft_entra', 'microsoft_entra_id', 'azure_ad', 'azure_active_directory'],
    keys: ['microsoft/entra', 'microsoft/entra_id', 'microsoft/microsoft_entra', 'microsoft/azure_active_directory'],
  },
  { names: ['microsoft_teams', 'ms_teams'], keys: ['microsoft/teams', 'microsoft/microsoft_teams', 'microsoft/microsoft_teams_*'] },
  { names: ['microsoft_edge', 'ms_edge', 'edge_browser', 'edge_chromium'], keys: ['microsoft/edge_chromium', 'microsoft/microsoft_edge_*'] },
  {
    names: ['sccm', 'mecm', 'configmgr', 'config_manager', 'configuration_manager', 'microsoft_configuration_manager', 'system_center_configuration_manager', 'endpoint_configuration_manager'],
    keys: ['microsoft/configuration_manager', 'microsoft/microsoft_configuration_manager', 'microsoft/microsoft_configuration_manager_*'],
  },

  // Virtualisation
  { names: ['esxi', 'vmware_esxi', 'esx', 'vmware_esx'], keys: ['vmware/esxi', 'vmware/esx'] },
  { names: ['vcenter', 'vcenter_server', 'vmware_vcenter', 'vmware_vcenter_server', 'vcsa'], keys: ['vmware/vcenter_server', 'vmware/vcenter', 'broadcom/vmware_vcenter', 'broadcom/vmware_vcenter_server'] },
  { names: ['vmware_horizon', 'omnissa_horizon', 'horizon_view'], keys: ['vmware/horizon', 'omnissa/horizon'] },
  { names: ['proxmox', 'proxmox_ve', 'proxmox_virtual_environment', 'pve'], keys: ['proxmox/virtual_environment', 'proxmox_server_solutions_gmbh/proxmox_virtual_environment_*'] },

  // Network and security gear
  {
    names: ['asa', 'cisco_asa', 'adaptive_security_appliance', 'cisco_adaptive_security_appliance'],
    keys: ['cisco/adaptive_security_appliance_software', 'cisco/cisco_secure_firewall_adaptive_security_appliance_*', 'cisco/secure_firewall_adaptive_security_appliance_*'],
  },
  {
    names: ['ftd', 'cisco_ftd', 'firepower', 'cisco_firepower', 'firepower_threat_defense', 'secure_firewall_threat_defense'],
    keys: ['cisco/firepower_threat_defense', 'cisco/cisco_secure_firewall_threat_defense_*', 'cisco/secure_firewall_adaptive_security_appliance_asa_and_secure_firewall_threat_defense_ftd'],
  },
  { names: ['ise', 'cisco_ise', 'identity_services_engine', 'cisco_identity_services_engine'], keys: ['cisco/identity_services_engine', 'cisco/cisco_identity_services_engine_*'] },
  {
    names: ['anyconnect', 'cisco_anyconnect', 'secure_client', 'cisco_secure_client'],
    keys: ['cisco/anyconnect_secure_mobility_client', 'cisco/secure_client', 'cisco/cisco_secure_client_*'],
  },
  { names: ['meraki', 'cisco_meraki'], keys: ['cisco/meraki_*', 'cisco/cisco_meraki_*'] },
  { names: ['ios_xe', 'cisco_ios_xe'], keys: ['cisco/ios_xe', 'cisco/cisco_ios_xe_software'] },
  { names: ['ios_xr', 'cisco_ios_xr'], keys: ['cisco/ios_xr', 'cisco/cisco_ios_xr_software'] },
  { names: ['nx_os', 'nxos', 'cisco_nx_os'], keys: ['cisco/nx_os', 'cisco/cisco_nx_os_software', 'cisco/cisco_nx_os_system_software_in_aci_mode'] },
  {
    names: ['netscaler', 'netscaler_adc', 'netscaler_gateway', 'citrix_adc', 'citrix_netscaler', 'citrix_gateway'],
    keys: ['citrix/netscaler', 'netscaler/adc', 'netscaler/gateway', 'citrix_netscaler/adc', 'citrix_netscaler/gateway', 'citrix/netscaler_adc_and_netscaler_gateway'],
  },
  {
    names: ['pulse_secure', 'pulse_connect_secure', 'connect_secure', 'ivanti_connect_secure'],
    keys: ['ivanti/connect_secure', 'pulsesecure/pulse_connect_secure', 'ivanti/ivanti_connect_secure'],
  },
  { names: ['unifi', 'ubiquiti_unifi'], keys: ['ubiquiti/unifi_*', 'ubiquiti_inc/unifi_*'] },
  { names: ['epmm', 'ivanti_epmm', 'mobileiron', 'mobileiron_core', 'endpoint_manager_mobile'], keys: ['ivanti/endpoint_manager_mobile', 'ivanti/endpoint_manager_mobile_*'] },

  // Servers, databases and developer tools
  { names: ['apache', 'apache_http_server', 'apache_httpd', 'httpd', 'apache2', 'apache_web_server'], keys: ['apache/http_server', 'apache_software_foundation/apache_http_server'] },
  { names: ['tomcat', 'apache_tomcat'], keys: ['apache/tomcat', 'apache_software_foundation/apache_tomcat'] },
  { names: ['nginx', 'nginx_open_source', 'nginx_plus', 'f5_nginx'], keys: ['f5/nginx', 'nginx/nginx', 'f5/nginx_open_source', 'f5/nginx_plus'] },
  { names: ['mysql', 'mysql_server', 'oracle_mysql'], keys: ['oracle/mysql', 'oracle/mysql_server', 'oracle_corporation/mysql_server'] },
  { names: ['mariadb', 'mariadb_server'], keys: ['mariadb/mariadb', 'mariadb/server'] },
  { names: ['mongodb', 'mongo', 'mongodb_server'], keys: ['mongodb/mongodb', 'mongodb/mongodb_server'] },
  { names: ['oracle_database', 'oracle_db', 'oracle_database_server'], keys: ['oracle/database_server', 'oracle_corporation/oracle_database_server'] },
  { names: ['node', 'node_js', 'nodejs'], keys: ['nodejs/node_js', 'nodejs/node'] },
  { names: ['jenkins'], keys: ['jenkins/jenkins', 'jenkins_project/jenkins'] },
  { names: ['grafana'], keys: ['grafana/grafana', 'grafana/grafana_oss', 'grafana/grafana_enterprise'] },
  { names: ['jira', 'jira_software', 'jira_server', 'jira_data_center'], keys: ['atlassian/jira_data_center', 'atlassian/jira_server', 'atlassian/jira_software_data_center', 'atlassian/jira_software_server'] },
  { names: ['github_enterprise', 'github_enterprise_server', 'ghes'], keys: ['github/enterprise_server'] },
  { names: ['crushftp'], keys: ['crushftp/crushftp'] },
  { names: ['moveit', 'moveit_transfer', 'progress_moveit'], keys: ['progress/moveit_transfer', 'progress_software/moveit_transfer', 'progress_software_corporation/moveit_transfer'] },
  { names: ['n8n'], keys: ['n8n_io/n8n', 'n8n/n8n'] },
];

const LINE_BY_NAME = new Map(PRODUCT_LINES.flatMap((line) => line.names.map((n) => [n, line] as const)));

export interface LineMatch {
  line: ProductLine;
  /** A version written into the name ("RHEL 9"), or null. */
  version: string | null;
}

/**
 * The line a candidate names. The name is tried as written, without the vendor
 * the model gave ("Microsoft Exchange"), and with it in front ("Teams" from
 * Microsoft is `microsoft_teams`, so a bare "Teams" isn't). Only the given
 * vendor counts: a first word may not be one ("Azure AD" is not "AD"). Failing
 * that, a version at the end of the name is split off ("RHEL 9", "Windows 11 24H2"),
 * longest name first.
 */
export function lineFor(name: string, vendor: string | null): LineMatch | null {
  const key = normalizeKey(name);
  if (!key) return null;
  const v = normalizeKey(vendor);
  const find = (k: string) => {
    for (const t of [k, ...(v ? [k.startsWith(`${v}_`) ? k.slice(v.length + 1) : '', `${v}_${k}`] : [])]) {
      const line = t ? LINE_BY_NAME.get(t) : undefined;
      if (line) return line;
    }
    return null;
  };
  const whole = find(key);
  if (whole) return { line: whole, version: whole.version ?? null };
  for (let i = key.length - 1; i > 0; i--) {
    if (!/\d/.test(key[i + 1] ?? '')) continue;
    // "rhel_8", or run together as "rhel8".
    const end = key[i] === '_' ? i : /[a-z]/.test(key[i]!) ? i + 1 : -1;
    if (end < 0) continue;
    const line = find(key.slice(0, end));
    if (line) return { line, version: key.slice(i + 1) };
  }
  return null;
}

/**
 * Key ranges that read a line's products: [from, to) on the catalog's
 * primary key. A whole key ends just after itself (' ' sorts before every
 * character a key holds); a prefix runs to its last character's successor.
 */
export function lineRanges(line: ProductLine): [string, string][] {
  return line.keys.map((k) => {
    if (!k.endsWith('*')) return [k, `${k} `];
    const p = k.slice(0, -1);
    return [p, p.slice(0, -1) + String.fromCharCode(p.charCodeAt(p.length - 1) + 1)];
  });
}

/** Whether a catalog key belongs to the line: a whole key it lists, or a prefix match `keep` allows. */
export function inLine(line: ProductLine, key: string): boolean {
  return line.keys.some((k) => {
    if (!k.endsWith('*')) return k === key;
    const p = k.slice(0, -1);
    return key.startsWith(p) && key.length > p.length && (!line.keep || line.keep.test(key.slice(p.length)));
  });
}

/**
 * The line's products a version points at: those whose product key holds the
 * version as whole segments ("9" in `red_hat_enterprise_linux_9`, "24H2" in
 * `windows_11_version_24h2`). Failing that, its leading parts with digits
 * ("10" of "10 Pro", "2019" of "2019 CU14"). Empty when it names none of them.
 */
export function forVersion<T extends { product: string | null }>(rows: T[], version: string | null): T[] {
  const v = normalizeKey(version);
  if (!v) return [];
  const holding = (s: string) => rows.filter((r) => `_${r.product ?? ''}_`.includes(`_${s}_`));
  const whole = holding(v);
  if (whole.length > 0) return whole;
  const parts = v.split('_');
  const n = parts.findIndex((p) => !/\d/.test(p));
  return n > 0 ? holding(parts.slice(0, n).join('_')) : [];
}

/** True when the line's products are one per release (`windows_10_version_22h2`, `red_hat_enterprise_linux_9`). */
export function perRelease(rows: { product: string | null }[]): boolean {
  return rows.some((r) => /_\d/.test(r.product ?? ''));
}

/** The plain key used when the catalog has nothing for a line yet. */
export function fallbackKey(line: ProductLine): string | null {
  return line.keys.find((k) => !k.endsWith('*')) ?? null;
}
