// Optional secrets, which `wrangler types` cannot infer (it only sees secrets
// listed in .dev.vars or declared as required).
declare namespace Cloudflare {
  interface Env {
    /** Optional. Raises the GitHub API limit from 60/h to 5,000/h. */
    GITHUB_TOKEN?: string;
  }
}
interface Env {
  GITHUB_TOKEN?: string;
}
