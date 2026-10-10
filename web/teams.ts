import type { Team } from '../src/stack/format';
import { itemMarks } from './format';

/**
 * Teams as the results page shows them. An item's team is the `;team` at the
 * end of it in the stack, set only for enterprise descriptions (Jev first,
 * then src/stack/teams.ts) or by hand on the Edit page. Grouping by team only
 * groups: it never reorders within a team or hides a result.
 */

export type TeamGroup = Team | 'unassigned';

export const TEAM: Record<TeamGroup, { label: string; note: string }> = {
  network: { label: 'Network', note: 'Routers, switches, firewalls, VPNs, load balancers and wireless.' },
  database: { label: 'Database', note: 'Database servers and data stores.' },
  frontend: { label: 'Front-end', note: 'Browser frameworks, UI libraries and front-end build tools.' },
  backend: { label: 'Back-end', note: 'Application dependencies: packages your services are built from.' },
  platform: { label: 'Platform', note: 'Servers and their operating systems, web servers, containers, virtualisation and CI/CD.' },
  endpoints: { label: 'Endpoints', note: 'Desktops, laptops and phones: their operating systems, browsers, office apps and clients.' },
  business: { label: 'Business apps', note: 'Mail, collaboration, CMS, ERP and CRM.' },
  unassigned: { label: 'Unassigned', note: 'Items with no team yet. Set one with Edit stack.' },
};

/** Every group in display order, Unassigned last. */
export const TEAM_GROUPS = Object.keys(TEAM) as TeamGroup[];

/** The team an item carries, or Unassigned. */
export function teamOf(item: string): TeamGroup {
  return itemMarks(item).team ?? 'unassigned';
}
