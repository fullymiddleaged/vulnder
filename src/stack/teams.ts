import { CATEGORIES } from '../resolve/aliases';
import { ownValue } from '../lib/normalize';
import type { StackItem, Team } from './format';

/**
 * A best guess at which team usually looks after a stack item, from a fixed
 * table: packages by ecosystem and name, products by the network patterns
 * resolving already uses, then keywords in `vendor_product`, then vendor.
 * Jev's answer, which reads the person's own description, always comes first
 * (src/resolve/profile.ts markTeams); this fills what Jev left unanswered, and
 * names an item added by hand to a stack that has teams. Null means Unassigned.
 */

/** npm packages that run in the browser or build for it. Names are already lowercase. */
const FRONTEND_NPM =
  /^(@(angular|vue|sveltejs|remix-run|babel|vitejs|nuxt|nuxtjs|emotion|mui|chakra-ui|tanstack|react-native)\/|(react|vue|svelte|angular|ember|jquery|bootstrap|webpack|vite|rollup|postcss|tailwindcss|sass|less|next|nuxt|gatsby|astro|preact|solid|lit|backbone|handlebars|dompurify|parcel|esbuild|three|d3|chart\.js|highlight\.js)(-|$))/;

/** Clients and agents that network vendors ship for desktops and phones. */
const NETWORK_CLIENTS = /(^|_)(client|agent|app|webex|jabber|anyconnect|forticlient|secure_client)(_|$)/;

/** Vendors whose products are network gear unless a keyword says otherwise. */
const NETWORK_VENDORS = new Set([
  'arista',
  'arista_networks',
  'aruba',
  'check_point',
  'checkpoint',
  'cisco',
  'd_link',
  'dlink',
  'draytek',
  'extremenetworks',
  'f5',
  'fortinet',
  'juniper',
  'mikrotik',
  'netgear',
  'netscaler',
  'palo_alto_networks',
  'paloaltonetworks',
  'pulsesecure',
  'ruckuswireless',
  'sonicwall',
  'tp_link',
  'tp_link_systems_inc',
  'ubiquiti',
  'ubiquiti_inc',
  'watchguard',
  'zyxel',
]);

/**
 * Edge gear in `vendor_product`: VPN and remote-access gateways, edge firewalls
 * and routers, SD-WAN edges, ADCs and load balancers, web application firewalls
 * and mail gateways. Checked against the catalog's real keys, vendor spellings
 * included (`sonicwall/sma1000`, `ubiquiti_inc/unifi_gateways`).
 */
const EDGE = new RegExp(
  [
    'netscaler|big_ip|loadmaster|load_balancer|(^|_)adc(_|$)',
    'connect_secure|policy_secure|pulse_connect|openvpn_access_server|sonicwall_sma|(^|_)(ip|mp|ssl)?vpn(_|$)|ztna|access_gateway|secure_access',
    'fireware|sonicos|pan_os|ngfw|fortios|fortigate|fortiproxy|adaptive_security|threat_defense|enterprise_firewall|routeros',
    'fortiweb|(^|_)waf(_|$)',
    'fortimail|secure_email_gateway|cisco_secure_email|email_protection_gateway|email_security_gateway',
    'sd_wan_gateway|velocloud_edge|edgeconnect|unifi_gateway|cloud_gateways|dream_router|fortress_gateway|omada_gateway',
  ].join('|'),
);

/** Remote-support tools that run as an internet-facing portal; edge by role, but not the network team's. */
const EDGE_APPS = /screenconnect/;

/** Their consoles and the clients people install sit inside the network, so they never count as edge. */
const EDGE_EXCLUDE = /manage(ment|r)|(^|_)(app|agent|client)(_|$)|anyconnect|globalprotect|forticlient/;

/** The product categories that are edge gear by what they are. */
const EDGE_CATEGORIES = CATEGORIES.filter((c) => c.name === 'firewall' || c.name === 'vpn');

/** Keywords in `vendor_product`, tested in this order: an earlier team wins. */
const KEYWORDS: [Team, RegExp][] = [
  // Edge gear first, so FortiMail stays with the network team rather than mail.
  ['network', EDGE],
  ['database', /sql|postgres|mongo|redis|elasticsearch|opensearch|cassandra|couchbase|clickhouse|neo4j|(^|_)db2(_|$)|memcached|database|mariadb|(^|_)[a-z0-9]*db(_|$)/],
  [
    'business',
    /(^|_)exchange(_server)?(_|$)|sharepoint|dynamics_365|(^|_)jira|confluence|wordpress|drupal|joomla|magento|typo3|moodle|salesforce|servicenow|netsuite|e_business_suite|peoplesoft|siebel|netweaver|business_objects|mediawiki|nextcloud|owncloud|roundcube|zimbra|sugarcrm|odoo|(^|_)(mail|email)(_|$)/,
  ],
  [
    'platform',
    /windows_server|linux|ubuntu|debian|enterprise_linux|centos|fedora|suse|freebsd|kubernetes|docker|containerd|(^|_)runc(_|$)|podman|openshift|rancher|jenkins|gitlab|github_enterprise|teamcity|bamboo|bitbucket|argo_cd|terraform|esxi|vcenter|vsphere|hyper_v|proxmox|nginx|http_server|httpd|tomcat|jetty|(^|_)iis(_|$)|internet_information_services|weblogic|websphere|jboss|wildfly|haproxy|traefik|envoy|openssl|openssh|samba|kafka|rabbitmq|activemq|zookeeper|hadoop|airflow|grafana|prometheus|kibana|logstash|splunk|artifactory|sonarqube|keycloak|active_directory|(^|_)bind(_\d|_|$)/,
  ],
  [
    'endpoints',
    /windows|macos|mac_os|iphone_os|ipados|watchos|android|chrome|firefox|thunderbird|safari|(^|_)edge(_chromium)?(_|$)|(^|_)office|(^|_)(word|excel|powerpoint|outlook|teams|visio|onenote)(_|$)|365_apps|acrobat|(^|_)reader(_|$)|(^|_)zoom|webex|7_zip|winrar|(^|_)vlc/,
  ],
];

/** Vendors that make one kind of thing, for products no keyword placed. */
const VENDORS: Record<string, Team> = {
  apple: 'endpoints',
  atlassian: 'business',
  hashicorp: 'platform',
  sap: 'business',
  vmware: 'platform',
};

/** Strips a repeated vendor prefix, as the catalog's category patterns expect. */
function bare(product: string, vendor: string): string {
  return product.startsWith(`${vendor}_`) ? product.slice(vendor.length + 1) : product;
}

function productTeam(vendor: string, raw: string): Team | null {
  const product = bare(raw, vendor);
  if (NETWORK_VENDORS.has(vendor) && NETWORK_CLIENTS.test(product)) return 'endpoints';
  if (CATEGORIES.some((c) => (ownValue(c.byVendor, vendor) ?? c.generic).test(product))) return 'network';
  // Keywords see the vendor too: `mongodb/server` and `linux/kernel` say what they are only together.
  const both = `${vendor}_${raw}`;
  for (const [team, pattern] of KEYWORDS) if (pattern.test(both)) return team;
  if (NETWORK_VENDORS.has(vendor)) return 'network';
  return ownValue(VENDORS, vendor) ?? null;
}

/**
 * True for a product that faces the internet by what it is: a VPN, an edge
 * firewall, a gateway or an ADC. Their results rank a little higher within
 * their priority (src/match/priority.ts); nothing else changes, so a wrong
 * answer here can only lift a result slightly, never lower one.
 */
export function isEdgeDevice(item: StackItem): boolean {
  if (item.kind !== 'product') return false;
  const product = bare(item.product, item.vendor);
  if (EDGE_EXCLUDE.test(product)) return false;
  const both = `${item.vendor}_${item.product}`;
  if (EDGE.test(both) || EDGE_APPS.test(both)) return true;
  return EDGE_CATEGORIES.some((c) => ownValue(c.byVendor, item.vendor)?.test(product) ?? false);
}

export function guessTeam(item: StackItem): Team | null {
  if (item.kind === 'product') return productTeam(item.vendor, item.product);
  if (item.ecosystem === 'GitHub Actions') return 'platform';
  if (item.ecosystem === 'npm' && FRONTEND_NPM.test(item.name)) return 'frontend';
  return 'backend';
}
