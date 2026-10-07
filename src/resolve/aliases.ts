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
  postgres: ['p:postgresql/postgresql'],
  postgresql: ['p:postgresql/postgresql'],
  mysql: ['p:oracle/mysql'],
  mariadb: ['p:mariadb/mariadb'],
  mongodb: ['p:mongodb/mongodb'],
  redis: ['p:redis/redis'],
  nginx: ['p:f5/nginx', 'p:nginx/nginx'],
  apache: ['p:apache/http_server'],
  httpd: ['p:apache/http_server'],
  apache_httpd: ['p:apache/http_server'],
  tomcat: ['p:apache/tomcat'],
  kubernetes: ['p:kubernetes/kubernetes'],
  k8s: ['p:kubernetes/kubernetes'],
  node: ['p:nodejs/node_js'],
  node_js: ['p:nodejs/node_js'],
  nodejs: ['p:nodejs/node_js'],
  openssl: ['p:openssl/openssl'],
  openssh: ['p:openbsd/openssh'],
  wordpress: ['p:wordpress/wordpress'],
  jenkins: ['p:jenkins/jenkins'],
  gitlab: ['p:gitlab/gitlab'],
  grafana: ['p:grafana/grafana'],
  ios_xe: ['p:cisco/ios_xe'],
  cisco_ios_xe: ['p:cisco/ios_xe'],
  fortigate: ['p:fortinet/fortios'],
  fortios: ['p:fortinet/fortios'],
  exchange: ['p:microsoft/exchange_server'],
  microsoft_exchange: ['p:microsoft/exchange_server'],
  vcenter: ['p:vmware/vcenter_server'],
  confluence: ['p:atlassian/confluence_data_center', 'p:atlassian/confluence_server'],
  jira: ['p:atlassian/jira_data_center', 'p:atlassian/jira_server'],
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
      juniper: /^junos$|^ex\d|qfx/,
      arista: /^eos$|switch/,
      hpe: /aruba|procurve|switch/,
      aruba: /arubaos|switch/,
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
      juniper: /^junos$|^mx\d|srx/,
      mikrotik: /routeros/,
      tp_link: /router|archer/,
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
      paloaltonetworks: /pan_os/,
      palo_alto_networks: /pan_os/,
      juniper: /srx|^junos$/,
      sonicwall: /sonicos|firewall/,
      sophos: /firewall|sfos/,
      checkpoint: /gaia|quantum|security_gateway/,
    },
  },
  {
    name: 'vpn',
    words: /\bvpns?\b/i,
    generic: /vpn/,
    byVendor: {
      cisco: /anyconnect|secure_client|adaptive_security|^asa|threat_defense/,
      fortinet: /fortios|fortigate|ssl_vpn/,
      paloaltonetworks: /globalprotect|pan_os/,
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
      aruba: /instant|arubaos/,
    },
  },
];

/**
 * Products that face the internet by what they are: VPN and remote-access
 * gateways, edge firewalls, application delivery controllers, web
 * application firewalls and mail gateways. Running one means exposing it,
 * and they make up much of CISA KEV, so they're marked internet-facing
 * without asking Jev. Patterns are tested like category patterns, against
 * product keys after stripping a repeated vendor prefix.
 */
export const EDGE_PRODUCTS: Record<string, RegExp> = {
  checkpoint: /quantum_security_gateway/,
  cisco: /adaptive_security|threat_defense|secure_email_gateway/,
  citrix: /netscaler/,
  f5: /^big_ip/,
  fortinet: /^(fortios|fortigate|fortiproxy|fortiweb|fortimail)/,
  ivanti: /connect_secure|policy_secure/,
  openvpn: /^access_server$/,
  palo_alto_networks: /^pan_os/,
  paloaltonetworks: /^pan_os/,
  pulsesecure: /pulse_connect_secure/,
  sonicwall: /^(sonicos|sma)/,
  watchguard: /^fireware/,
  zyxel: /^(usg|zywall)/,
};

/** Their management consoles and client apps sit inside, so they never count. */
export const EDGE_EXCLUDE = /manage(ment|r)|(^|_)(app|agent|client)(_|$)/;
