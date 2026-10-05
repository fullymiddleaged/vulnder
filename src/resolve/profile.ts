/**
 * Who a stack probably belongs to. The guess only reorders close matches, so a
 * home user asking about "Cisco switches" sees small-business gear first and an
 * enterprise sees Catalyst and Nexus first. It never hides or adds an item,
 * and exact matches are left alone.
 *
 * The classifier is a plain function of non-identifying signals, so another
 * classifier (for example a hosted one) can be swapped in and compared.
 */

export const PROFILES = ['enterprise', 'smb', 'home', 'cloud', 'developer'] as const;
export type Profile = (typeof PROFILES)[number];

export interface ProfileSignals {
  /** Exactly resolved products. */
  products: { vendor: string; product: string }[];
  /** Vendors behind vague inputs ("Netgear router"), which only have close matches. */
  vendors: string[];
  /** Direct package dependencies. */
  directPackages: number;
  /** What the extraction model said about the text; always null for manifests. */
  modelHint: Profile | null;
}

export interface ProfileGuess {
  profile: Profile | null;
  /** 0 to 1: how much the evidence agrees, scaled down when there is little of it. */
  confidence: number;
}

export type ProfileClassifier = (signals: ProfileSignals) => ProfileGuess | Promise<ProfileGuess>;

/** Below this, close matches keep their catalog order. */
export const MIN_RANK_CONFIDENCE = 0.5;

/**
 * Segment tags: which kinds of stack a product usually turns up in. The first
 * entry matching the vendor (and the product pattern, if any) wins, so
 * specific entries come before a vendor's catch-all. Patterns are tested
 * against catalog product keys, which may repeat the vendor (`cisco_ios_xe_software`).
 */
export interface Segment {
  vendor: string;
  product?: RegExp;
  profiles: Profile[];
}

export const SEGMENTS: Segment[] = [
  { vendor: 'cisco', product: /small_business|(^|_)(rv|sg|cbs|spa)\d|meraki|business_\d{3}/, profiles: ['smb', 'home'] },
  { vendor: 'cisco', profiles: ['enterprise'] },
  { vendor: 'microsoft', product: /azure|entra|exchange_online|microsoft_365|copilot|fabric/, profiles: ['cloud'] },
  { vendor: 'microsoft', product: /visual_studio|(^|_)net_\d|asp_?net|powershell|kiota|typescript/, profiles: ['developer'] },
  { vendor: 'microsoft', product: /exchange_server|sharepoint|skype_for_business|dynamics|active_directory|sql_server|windows_server/, profiles: ['enterprise', 'smb'] },
  { vendor: 'microsoft', product: /xbox|age_of_empires|hevc_video|pc_manager/, profiles: ['home'] },
  { vendor: 'google', product: /cloud|gke|gvisor|kubernetes/, profiles: ['cloud'] },
  { vendor: 'google', product: /nest|pixel|android|chromecast|home/, profiles: ['home'] },
  { vendor: 'google', product: /protobuf|(^|_)go_|cel_go|tink|adk|mcp_toolbox/, profiles: ['developer'] },
  { vendor: 'amazon', product: /kiro|strands|ion_|deep_java|mcp_server/, profiles: ['developer'] },
  { vendor: 'amazon', profiles: ['cloud'] },
  { vendor: 'aws', profiles: ['cloud'] },
  { vendor: 'kubernetes', profiles: ['cloud'] },
  { vendor: 'docker', profiles: ['cloud', 'developer'] },
  { vendor: 'hashicorp', profiles: ['cloud'] },
  { vendor: 'redhat', product: /openshift/, profiles: ['cloud'] },
  { vendor: 'vercel', profiles: ['cloud'] },
  { vendor: 'cloudflare', profiles: ['cloud'] },
  { vendor: 'atlassian', product: /data_center|_server/, profiles: ['enterprise'] },
  { vendor: 'atlassian', product: /sourcetree/, profiles: ['developer'] },
  { vendor: 'fortinet', product: /fortios|fortigate|fortiwifi/, profiles: ['enterprise', 'smb'] },
  { vendor: 'fortinet', profiles: ['enterprise'] },
  { vendor: 'juniper', profiles: ['enterprise'] },
  { vendor: 'palo_alto_networks', profiles: ['enterprise'] },
  { vendor: 'paloaltonetworks', profiles: ['enterprise'] },
  { vendor: 'checkpoint', profiles: ['enterprise'] },
  { vendor: 'check_point', profiles: ['enterprise'] },
  { vendor: 'f5', profiles: ['enterprise'] },
  { vendor: 'citrix', profiles: ['enterprise'] },
  { vendor: 'ivanti', profiles: ['enterprise'] },
  { vendor: 'vmware', profiles: ['enterprise'] },
  { vendor: 'broadcom', profiles: ['enterprise'] },
  { vendor: 'sap', profiles: ['enterprise'] },
  { vendor: 'oracle', product: /e_business|peoplesoft|weblogic|fusion|database_server|jd_edwards/, profiles: ['enterprise'] },
  { vendor: 'servicenow', profiles: ['enterprise'] },
  { vendor: 'splunk', profiles: ['enterprise'] },
  { vendor: 'solarwinds', profiles: ['enterprise', 'smb'] },
  { vendor: 'zohocorp', product: /manageengine/, profiles: ['enterprise', 'smb'] },
  { vendor: 'veeam', profiles: ['enterprise', 'smb'] },
  { vendor: 'sonicwall', profiles: ['smb'] },
  { vendor: 'sophos', profiles: ['smb'] },
  { vendor: 'watchguard', profiles: ['smb'] },
  { vendor: 'draytek', profiles: ['smb'] },
  { vendor: 'connectwise', profiles: ['smb'] },
  { vendor: 'kaseya', profiles: ['smb'] },
  { vendor: 'wordpress', profiles: ['smb'] },
  { vendor: 'zyxel', profiles: ['smb', 'home'] },
  { vendor: 'mikrotik', profiles: ['smb', 'home'] },
  { vendor: 'ubiquiti', profiles: ['smb', 'home'] },
  { vendor: 'synology', profiles: ['home', 'smb'] },
  { vendor: 'qnap', profiles: ['home', 'smb'] },
  { vendor: 'tp_link', profiles: ['home'] },
  { vendor: 'netgear', profiles: ['home'] },
  { vendor: 'd_link', profiles: ['home'] },
  { vendor: 'asus', profiles: ['home'] },
  { vendor: 'linksys', profiles: ['home'] },
  { vendor: 'tenda', profiles: ['home'] },
  { vendor: 'totolink', profiles: ['home'] },
  { vendor: 'wavlink', profiles: ['home'] },
  { vendor: 'plex', profiles: ['home'] },
  { vendor: 'home_assistant', profiles: ['home'] },
  { vendor: 'github', profiles: ['developer'] },
  { vendor: 'gitlab', profiles: ['developer'] },
  { vendor: 'jenkins', profiles: ['developer'] },
  { vendor: 'jetbrains', profiles: ['developer'] },
  { vendor: 'git_scm', profiles: ['developer'] },
  { vendor: 'nodejs', profiles: ['developer'] },
  { vendor: 'python', profiles: ['developer'] },
];

/** The segment tags for a catalog product, or none. */
export function segmentsOf(vendor: string, product?: string): Profile[] {
  const hit = SEGMENTS.find((s) => s.vendor === vendor && (s.product === undefined ? true : product !== undefined && s.product.test(product)));
  return hit?.profiles ?? [];
}

/** Vendor-wide tags only (entries without a product pattern), for vague inputs. */
function vendorSegments(vendor: string): Profile[] {
  return SEGMENTS.find((s) => s.vendor === vendor && s.product === undefined)?.profiles ?? [];
}

const WEIGHT = { product: 1, vendor: 0.5, package: 1, modelHint: 3 } as const;
/** Evidence worth this much counts as fully supported. */
const FULL_EVIDENCE = 3;

/** The default classifier: weighted votes from segment tags, packages and the model's hint. */
export function rulesClassifier(signals: ProfileSignals): ProfileGuess {
  const scores = new Map<Profile, number>();
  const vote = (profiles: Profile[], weight: number) => {
    for (const p of profiles) scores.set(p, (scores.get(p) ?? 0) + weight / profiles.length);
  };
  for (const { vendor, product } of signals.products) vote(segmentsOf(vendor, product), WEIGHT.product);
  for (const vendor of signals.vendors) vote(vendorSegments(vendor), WEIGHT.vendor);
  if (signals.directPackages > 0) vote(['developer'], signals.directPackages * WEIGHT.package);
  if (signals.modelHint) vote([signals.modelHint], WEIGHT.modelHint);

  const ranked = [...scores].sort((a, b) => b[1] - a[1]);
  const total = ranked.reduce((sum, [, s]) => sum + s, 0);
  const [top, second] = ranked;
  if (!top || total === 0 || (second && second[1] === top[1])) return { profile: null, confidence: 0 };
  const confidence = (top[1] / total) * Math.min(1, total / FULL_EVIDENCE);
  return { profile: top[0], confidence: Math.round(confidence * 100) / 100 };
}

export function classifyProfile(signals: ProfileSignals, classifier: ProfileClassifier = rulesClassifier): ProfileGuess | Promise<ProfileGuess> {
  return classifier(signals);
}

/**
 * Close matches that fit the profile first, then untagged ones, then ones
 * tagged for other kinds of stack. The sort is stable, so catalog order holds
 * within each group.
 */
export function rankByProfile<T>(items: T[], profile: Profile, keyOf: (item: T) => { vendor: string; product?: string } | null): T[] {
  const rank = (item: T) => {
    const key = keyOf(item);
    const tags = key ? segmentsOf(key.vendor, key.product) : [];
    if (tags.includes(profile)) return 0;
    return tags.length === 0 ? 1 : 2;
  };
  return items
    .map((item) => ({ item, r: rank(item) }))
    .sort((a, b) => a.r - b.r)
    .map(({ item }) => item);
}
