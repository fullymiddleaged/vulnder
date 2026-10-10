/**
 * Common names that do not match an identifier on their own: "Next.js" is the
 * npm package `next`, "Postgres" is the product postgresql/postgresql. Keys
 * are normalizeKey() output. A name with several entries is offered as a
 * choice. Contributions welcome: keep entries to identifiers that appear in
 * CVE records or advisories.
 */
export const ALIASES: Record<string, string[]> = {
  next: ['npm:next'],
  next_js: ['npm:next'],
  nextjs: ['npm:next'],
  react: ['npm:react'],
  express: ['npm:express'],
  express_js: ['npm:express'],
  angular: ['npm:@angular/core'],
  vue: ['npm:vue'],
  vue_js: ['npm:vue'],
  nuxt: ['npm:nuxt'],
  django: ['pypi:django'],
  flask: ['pypi:flask'],
  fastapi: ['pypi:fastapi'],
  fast_api: ['pypi:fastapi'],
  rails: ['gem:rails'],
  ruby_on_rails: ['gem:rails'],
  laravel: ['composer:laravel/framework'],
  symfony: ['composer:symfony/symfony'],
  spring: ['maven:org.springframework:spring-core'],
  spring_framework: ['maven:org.springframework:spring-core'],
  spring_boot: ['maven:org.springframework.boot:spring-boot'],
  log4j: ['maven:org.apache.logging.log4j:log4j-core'],
  // Products filed under several keys (Apache, Exchange, MySQL, …) are product lines (lines.ts) instead.
  postgres: ['p:postgresql/postgresql'],
  postgresql: ['p:postgresql/postgresql'],
  redis: ['p:redis/redis'],
  kubernetes: ['p:kubernetes/kubernetes'],
  k8s: ['p:kubernetes/kubernetes'],
  openssl: ['p:openssl/openssl'],
  openssh: ['p:openbsd/openssh'],
  wordpress: ['p:wordpress/wordpress'],
  gitlab: ['p:gitlab/gitlab'],
  fortigate: ['p:fortinet/fortios'],
  fortios: ['p:fortinet/fortios'],
  confluence: ['p:atlassian/confluence_data_center', 'p:atlassian/confluence_server'],
};

/**
 * Product categories. Catalog names rarely say what a product is (Cisco's
 * switch software is `ios_xe` and `nx_os`), so a vague "Cisco switches" is
 * expanded through these patterns into every fitting product of that vendor,
 * all marked as close matches. `words` is tested against what the user wrote;
 * `generic` and `byVendor` against catalog product keys, after stripping a
 * repeated vendor prefix (`cisco_ios_xe_software` is tested as `ios_xe_software`).
 */
export interface Category {
  name: string;
  words: RegExp;
  generic: RegExp;
  byVendor: Record<string, RegExp>;
}

export const CATEGORIES: Category[] = [
  {
    name: 'switch',
    words: /\bswitch(es)?\b/i,
    generic: /switch/,
    byVendor: {
      cisco: /(^|_)(ios_xe|nx_os)(_|$)|^ios(_software)?$|catalyst(?!_sd_wan)|nexus|switch|meraki_ms/,
      // Junos OS and Junos OS Evolved, not Junos Space (the management app).
      juniper: /^junos(_os(_evolved)?)?$|^ex\d|qfx/,
      arista: /^eos$|extensible_operating_system|switch/,
      hpe: /aruba|procurve|switch|aos_(cx|s)(_|$)/,
      ubiquiti: /unifi|edgeswitch/,
      fortinet: /fortiswitch/,
    },
  },
  {
    name: 'router',
    words: /\brouters?\b/i,
    generic: /router/,
    byVendor: {
      cisco: /(^|_)ios_(xe|xr)(_|$)|^ios(_software)?$|router|(^|_)(isr|asr)(\d|_|$)/,
      juniper: /^junos(_os(_evolved)?)?$|^mx\d|srx/,
      mikrotik: /routeros/,
      tp_link: /router|archer|^tl_wr/,
      netgear: /router|nighthawk/,
    },
  },
  {
    name: 'firewall',
    words: /\bfirewalls?\b/i,
    generic: /firewall/,
    byVendor: {
      cisco: /adaptive_security|^asa|firepower|secure_firewall|threat_defense|^ftd|^fmc/,
      fortinet: /fortios|fortigate|fortiproxy/,
      palo_alto_networks: /pan_os/,
      juniper: /srx|^junos(_os(_evolved)?)?$/,
      sonicwall: /sonicos|firewall/,
      sophos: /firewall|sfos/,
      checkpoint: /gaia|quantum|security_gateway|spark_firewall/,
    },
  },
  {
    name: 'vpn',
    words: /\bvpns?\b/i,
    generic: /vpn/,
    byVendor: {
      cisco: /anyconnect|secure_client|adaptive_security|^asa|threat_defense/,
      fortinet: /fortios|fortigate|ssl_vpn/,
      palo_alto_networks: /globalprotect|pan_os/,
      ivanti: /connect_secure|policy_secure|pulse/,
    },
  },
  {
    name: 'wireless',
    words: /\b(wireless|wi-?fi|access points?)\b/i,
    generic: /wireless|wlc|access_point|wifi/,
    byVendor: {
      cisco: /wireless|wlc|aironet|meraki_mr|catalyst_9800/,
      ubiquiti: /unifi/,
      hpe: /instant|arubaos/,
    },
  },
];

/**
 * Vendors stored under more than one key: CVE records carry each CNA's own
 * spelling ("Juniper Networks", "Ubiquiti Inc."), older data the short one.
 * Each family is named by the key CATEGORIES uses, and lists every key and
 * common word that means it; Aruba is HPE's. Checked against the catalog's
 * real vendor keys: a family missing a spelling makes "Juniper switches"
 * find nothing.
 */
const VENDOR_FAMILIES: Record<string, string[]> = {
  juniper: ['juniper', 'juniper_networks'],
  arista: ['arista', 'arista_networks'],
  hpe: ['hpe', 'hewlett_packard_enterprise', 'hewlett_packard_enterprise_hpe', 'aruba', 'aruba_networks', 'arubanetworks'],
  ubiquiti: ['ubiquiti', 'ubiquiti_inc', 'ubiquiti_networks'],
  tp_link: ['tp_link', 'tp_link_systems_inc', 'tp_link_system_inc', 'tplink'],
  palo_alto_networks: ['palo_alto_networks', 'paloaltonetworks', 'palo_alto', 'palo'],
  checkpoint: ['checkpoint', 'check_point', 'check_point_software'],
  sonicwall: ['sonicwall', 'sonicwall_inc'],
  apache: ['apache', 'apache_software_foundation'],
  oracle: ['oracle', 'oracle_corporation'],
  jenkins: ['jenkins', 'jenkins_project'],
  mariadb: ['mariadb', 'mariadb_corporation'],
  red_hat: ['red_hat', 'redhat'],
  sap: ['sap', 'sap_se'],
  zoom: ['zoom', 'zoom_communications', 'zoom_communications_inc', 'zoom_video_communications'],
  proxmox: ['proxmox', 'proxmox_server_solutions_gmbh'],
  mongodb: ['mongodb', 'mongodb_inc'],
  d_link: ['d_link', 'dlink', 'd_link_corporation'],
  progress: ['progress', 'progress_software', 'progress_software_corporation'],
  n8n: ['n8n', 'n8n_io'],
  wolfssl: ['wolfssl', 'wolfssl_inc'],
};

const FAMILY_OF = new Map(Object.entries(VENDOR_FAMILIES).flatMap(([family, keys]) => keys.map((k) => [k, family] as const)));

/** The family a vendor key or word belongs to; a vendor with one spelling is its own. */
export function vendorFamily(vendor: string): string {
  return FAMILY_OF.get(vendor) ?? vendor;
}

/** Every key a vendor may be stored under, the given one first. */
export function vendorSpellings(vendor: string): string[] {
  const family = FAMILY_OF.get(vendor);
  return family ? [vendor, ...VENDOR_FAMILIES[family]!.filter((k) => k !== vendor)] : [vendor];
}
