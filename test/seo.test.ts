import { describe, expect, it } from 'vitest';
import { app } from '../src/index';
import { indexable } from '../web/url';

describe('search indexing', () => {
  it('lets only the bare page be indexed', () => {
    expect(indexable('')).toBe(true);
    expect(indexable('?utm_source=x')).toBe(true);
    expect(indexable('?s=npm:next@14.2.3')).toBe(false);
    expect(indexable('?days=7&s=')).toBe(false);
  });

  it('marks every Worker response noindex', async () => {
    for (const path of ['/api/nope', '/feed.xml', '/badge.svg']) {
      const res = await app.request(path, {}, {});
      expect(res.headers.get('X-Robots-Tag'), path).toBe('noindex');
    }
  });
});
