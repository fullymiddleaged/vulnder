import type { Ecosystem } from '../lib/normalize';

/** Something a stack might contain, before it is resolved to a stack item. */
export type Candidate =
  | {
      kind: 'package';
      ecosystem: Ecosystem;
      name: string;
      /** Only exact versions; ranges like ^1.2 are dropped rather than guessed at. */
      version: string | null;
      /** False for transitive dependencies from a lockfile. */
      direct: boolean;
    }
  | {
      kind: 'product';
      /** Free-form product name, e.g. "nginx" or "IOS XE". */
      name: string;
      vendor: string | null;
      version: string | null;
      direct: boolean;
    };

export interface ManifestParser {
  /** Short ID, e.g. 'package-lock.json'. */
  id: string;
  /** True when a file name says this is the format (the name only, no path). */
  matchesFilename(filename: string): boolean;
  /** True when content alone identifies the format, for pasted text. */
  sniff(text: string): boolean;
  /** Returns candidates; throws if the text is not this format after all. */
  parse(text: string): Candidate[];
}
