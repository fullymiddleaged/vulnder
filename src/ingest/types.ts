import type { Budget } from './budget';
import type { Store } from './store';

export type SourceName = 'cve' | 'ghsa' | 'kev' | 'epss';

/** Sources that can supply affected rows. */
export type AffectedSource = 'cve' | 'ghsa' | 'kev';

export interface Ref {
  url: string;
  tags?: string[];
}

export interface Ssvc {
  exploitation: string | null;
  automatable: string | null;
  technicalImpact: string | null;
}

export type SeverityLabel = 'critical' | 'high' | 'medium' | 'low';

/**
 * A source's word for severity, on one scale. CNAs following Red Hat say
 * important and moderate; GitHub says moderate in older advisories.
 */
export function parseSeverityLabel(text: unknown): SeverityLabel | null {
  if (typeof text !== 'string') return null;
  switch (text.trim().toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
    case 'important':
      return 'high';
    case 'medium':
    case 'moderate':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return null;
  }
}

/** Vulnerability fields a source can set. Absent means "this source says nothing". */
export interface VulnFields {
  title: string | null;
  summary: string | null;
  publishedAt: string | null;
  modifiedAt: string | null;
  cvssScore: number | null;
  cvssVector: string | null;
  /** The source's severity word, kept for when no source gives a CVSS score. */
  severityLabel: SeverityLabel | null;
  cwe: string[];
  refs: Ref[];
  ssvc: Ssvc | null;
  epss: number;
  epssPercentile: number;
  epssDate: string;
  kevAddedAt: string;
  kevRansomware: boolean;
  kevDueDate: string | null;
  kevRequiredAction: string | null;
}

export interface AffectedInput {
  kind: 'package' | 'product';
  ecosystem?: string | null;
  packageName?: string | null;
  vendor?: string | null;
  product?: string | null;
  label?: string | null;
  ranges: unknown[];
  fixedVersion?: string | null;
}

/**
 * One source's view of one vulnerability. Ingest merges patches into the
 * stored record; it never replaces a whole record from one source.
 */
export interface VulnPatch {
  source: SourceName;
  /** CVE ID when known, otherwise the source's own ID (e.g. GHSA). */
  id: string;
  /** Other IDs for the same vulnerability. */
  aliases: string[];
  fields: Partial<VulnFields>;
  /** Replaces this source's affected rows. Undefined leaves them alone. */
  affected?: AffectedInput[];
  /** CVE REJECTED, or GHSA withdrawn. */
  withdrawn?: boolean;
}

export interface SourceContext {
  /** Charges the run budget. Always use this, never the global fetch. */
  fetch: typeof fetch;
  store: Store;
  budget: Budget;
  now: () => Date;
  log: (message: string) => void;
  githubToken?: string;
  /** 'node' allows heavier fallbacks (e.g. the 24 MB deltaLog.json). */
  runtime: 'worker' | 'node';
  /** Waits between paced or retried calls; setTimeout when left out. */
  sleep?: (ms: number) => Promise<void>;
}

export interface FetchResult<C> {
  records: VulnPatch[];
  nextCursor: C;
  /** True when the source has nothing more to fetch for now. */
  done: boolean;
}

/** The common interface every data source implements. */
export interface Source<C> {
  name: SourceName;
  initialCursor(now: Date): C;
  fetchChanges(cursor: C, ctx: SourceContext): Promise<FetchResult<C>>;
}
