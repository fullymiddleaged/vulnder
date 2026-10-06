/**
 * A free first screen for prompt injection: phrases that only make sense as
 * instructions to an AI. A hit refuses the text before any model call, so a
 * pattern here must never match a real stack ("System Center", "Prompt
 * Security", "Jenkins agent"); test/injection.test.ts checks that, and
 * measures recall against real jailbreaks. Jev screens what this misses.
 *
 * Every pattern is bounded, so matching stays linear in the input.
 */

// Stack descriptions talk about rules, modes and filters too ("override the
// default rules", "Chromebook in developer mode", "a jailbroken iPhone", "S3
// without restrictions"), so each pattern needs wording aimed at an AI.
const PATTERNS: RegExp[] = [
  // "ignore all previous instructions", "disregard your guidelines"
  /\b(ignore|disregard|forget)\b.{0,40}?\b(previous|prior|above|earlier|preceding|all|any|your|these|those)\b.{0,20}?\b(instructions?|prompts?|rules|guidelines|directives?|programming)\b/,
  /\b(override|bypass)\b.{0,30}?\b(your|its)\b.{0,20}?\b(instructions?|programming|guidelines|safety|content policy)\b/,
  /\bnew instructions?\s*[:*!]/,
  /\b(system|developer|initial|hidden|original) prompt\b/,
  /\b(god|dan|jailbreak|unrestricted|unfiltered) mode\b/,
  /\b(chatgpt|ai|assistant|model) (with|in) developer mode\b|\bdeveloper mode (output|response)s?\b/,
  /\bdo anything now\b/,
  /\bwithout (any )?(censorship|ethical|moral)\b/,
  // Role play: "you are now", "from now on you", "pretend you are", "stay in character"
  /\byou are (now|no longer|going to (act|pretend|be)|about to (immerse|become|play))\b/,
  /\bfrom now on,? (you|your|act|respond|answer|reply)\b/,
  /\b(pretend|imagine) (that )?(you are|you're|to be)\b/,
  /\bi want you to (act|pretend|be|play|respond|answer|reply|ignore)\b/,
  /\b(stay|remain|break) (in|out of) character\b/,
  // Chat-template tokens
  /<\|?\s*(im_start|im_end|system|endoftext)\s*\|?>|\[\/?inst\]|<<\/?sys>>|\{\s*"role"\s*:/,
];

/** Lowercased, with format characters (zero-width joiners and the like) removed and whitespace collapsed. */
function prepare(text: string): string {
  return text.normalize('NFKC').replace(/\p{Cf}/gu, '').replace(/\s+/g, ' ').toLowerCase();
}

export function looksLikeInjection(text: string): boolean {
  const t = prepare(text);
  return PATTERNS.some((p) => p.test(t));
}
