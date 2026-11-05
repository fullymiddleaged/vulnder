import { describe, expect, it } from 'vitest';
import page from '../public/index.html?raw';
import { parseStack, serializeStack } from '../src/stack/format';
import { itemLabel, itemMarks, RISK } from '../web/format';

// The home page's sample result is static HTML: these keep it saying what the app would draw.
const sample = page.slice(page.indexOf('<section class="sample"'), page.indexOf('</section>'));

describe('home page sample result', () => {
  it('is on the page', () => {
    expect(sample).toContain('What a result looks like');
  });

  it('links to a stack that parses and holds every item it shows', () => {
    const href = /href="(\/\?s=[^"]+)">See the full example/.exec(sample)?.[1];
    expect(href).toBeDefined();
    const params = new URLSearchParams(href!.slice(1).replaceAll('&amp;', '&'));
    expect(params.get('days')).toBe('90');
    const stack = parseStack(params.get('s')!);
    expect(stack).toHaveLength(6);
    const items = serializeStack(stack).split(',');
    const shown = [...sample.matchAll(/<code title="([^"]+)">(.*?)<\/code>/g)];
    expect(shown).toHaveLength(3);
    for (const [, title, text] of shown) {
      expect(items.map((i) => itemMarks(i).name)).toContain(title);
      const { label, ecosystem } = itemLabel(title!);
      expect(text).toBe(ecosystem ? `<span class="ecosystem">${ecosystem}</span>${label}` : label);
    }
  });

  it('labels its pills as the tiers are named', () => {
    const labels = [...sample.matchAll(/<span class="pill (\w+)">\d+ ([^<]+)<\/span>/g)];
    expect(labels.length).toBeGreaterThan(0);
    for (const [, light, label] of labels) {
      const tier = Object.values(RISK).find((r) => r.light === light);
      expect(label).toBe(tier?.label.toLowerCase());
    }
  });
});
