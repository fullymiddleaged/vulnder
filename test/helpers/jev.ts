/** Jev replies in the documented shape, for tests. */
export function jevReply(answers: Record<string, unknown>) {
  return { model: 'jev-1.13.0', answers, usage: { input_tokens: 300, output_tokens: 0 } };
}

export const noul = (p: number) => ({ type: 'noul', noul: p, confidence: Math.max(p, 1 - p) });

export const choice = (value: string, confidence: number) => ({ type: 'choice', choice: value, confidence, probabilities: { [value]: confidence } });

/** A screen that finds nothing wrong and no profile. */
export const CLEAN_SCREEN = jevReply({ injection: noul(0.02), scale: choice('unclear', 0.9), hosting: choice('unclear', 0.9) });
