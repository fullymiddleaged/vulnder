import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { fromInventory, isProduct, productName, vendorName } from '../src/resolve/inventory';
import { fitItems } from '../src/routes/api';
import type { Chip } from '../src/resolve/catalog';

describe('productName', () => {
  it.each([
    ['Google Chrome', 'Google Chrome'],
    ['7-Zip 23.01 (x64)', '7-Zip'],
    ['Mozilla Firefox (x64 en-US)', 'Mozilla Firefox'],
    ['Python 3.12.1 (64-bit)', 'Python'],
    ['Microsoft 365 Apps for enterprise - en-us', 'Microsoft 365 Apps for enterprise'],
    ['Notepad++ (64-bit x64)', 'Notepad++'],
    ['Zoom Workplace (User)', 'Zoom Workplace'],
    ['VLC media player 3.0.20', 'VLC media player'],
    ['FortiClient VPN v7.2.4.0972', 'FortiClient VPN'],
    ['Java 8 Update 401', 'Java 8 Update 401'],
    ['Node.js', 'Node.js'],
    ['Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33135', 'Microsoft Visual C++ 2015-2022 Redistributable'],
    // A bracket that says something about the product stays.
    ['Visual Studio Code (Insiders)', 'Visual Studio Code (Insiders)'],
    ['  Adobe   Acrobat  ', 'Adobe Acrobat'],
  ])('%s → %s', (display, want) => {
    expect(productName(display)).toBe(want);
  });

  it('never returns an empty name, and keeps names short', () => {
    expect(productName('1.2.3')).toBe('1.2.3');
    expect(productName('(x64)')).toBe('(x64)');
    expect(productName('a'.repeat(500))).toHaveLength(100);
  });
});

describe('vendorName', () => {
  it.each([
    ['Google LLC', 'Google'],
    ['Mozilla Corporation', 'Mozilla'],
    ['Zoom Video Communications, Inc.', 'Zoom Video Communications'],
    ['Fortinet Inc', 'Fortinet'],
    ['Igor Pavlov', 'Igor Pavlov'],
    ['TeamViewer Germany GmbH', 'TeamViewer Germany'],
  ])('%s → %s', (publisher, want) => {
    expect(vendorName(publisher)).toBe(want);
  });

  it('gives null for a missing or empty publisher', () => {
    expect(vendorName(null)).toBeNull();
    expect(vendorName('   ')).toBeNull();
    expect(vendorName('Inc.')).toBeNull();
  });
});

describe('isProduct', () => {
  it.each(['Update for Windows 10 for x64-based Systems (KB5001716)', 'Security Update for Microsoft Office (KB5002469)', 'Hotfix for Microsoft .NET', 'KB5034441', 'Microsoft.VCLibs.140.00.UWPDesktop', 'Microsoft.UI.Xaml.2.8', 'English (United States) Local Experience Pack'])(
    'ignores %s',
    (name) => expect(isProduct(name)).toBe(false),
  );
  it.each(['Microsoft Edge', 'Microsoft.DesktopAppInstaller', 'Microsoft Update Health Tools', 'Notepad++'])('keeps %s', (name) => expect(isProduct(name)).toBe(true));
});

describe('fromInventory', () => {
  it('collapses versions and names, keeping a version only when the fleet runs one', () => {
    const inv = fromInventory(
      [
        { displayName: 'Mozilla Firefox (x64 en-US)', version: '131.0.3', publisher: 'Mozilla', deviceCount: 40 },
        { displayName: 'Mozilla Firefox (x64 en-GB)', version: '130.0.1', publisher: 'Mozilla', deviceCount: 5 },
        { displayName: '7-Zip 23.01 (x64)', version: '23.01', publisher: 'Igor Pavlov', deviceCount: 12 },
        { displayName: 'Update for Windows (KB5001716)', version: '1.0', publisher: 'Microsoft Corporation', deviceCount: 300 },
        { displayName: 'FortiClient VPN', version: null, publisher: 'Fortinet Inc', deviceCount: 3 },
      ],
      200,
    );
    expect(inv.candidates).toEqual([
      { kind: 'product', name: 'Mozilla Firefox', vendor: 'Mozilla', version: null, direct: true },
      { kind: 'product', name: '7-Zip', vendor: 'Igor Pavlov', version: '23.01', direct: true },
      { kind: 'product', name: 'FortiClient VPN', vendor: 'Fortinet', version: null, direct: true },
    ]);
    expect(inv).toMatchObject({ notChecked: [], ignored: 1 });
  });

  it('fills the limit with the products on most devices, and names the rest', () => {
    const entries = Array.from({ length: 5 }, (_, i) => ({ displayName: `App ${'abcde'[i]}`, publisher: 'Acme Ltd', deviceCount: i + 1 }));
    const inv = fromInventory(entries, 3);
    expect(inv.candidates.map((c) => c.name)).toEqual(['App e', 'App d', 'App c']);
    expect(inv.notChecked).toEqual(['App b (Acme)', 'App a (Acme)']);
  });

  it('counts a missing device count as one, and keeps the same name from two publishers apart', () => {
    const inv = fromInventory(
      [
        { displayName: 'Agent', publisher: 'Acme' },
        { displayName: 'Agent', publisher: 'Other Co', deviceCount: 2 },
        { displayName: '' },
        { displayName: '!!!' },
      ],
      10,
    );
    expect(inv.candidates.map((c) => [c.name, c.kind === 'product' ? c.vendor : null])).toEqual([
      ['Agent', 'Other'],
      ['Agent', 'Acme'],
    ]);
    expect(inv.ignored).toBe(2);
  });

  it('never throws, and every candidate is short and named, whatever the inventory holds', () => {
    const text = fc.oneof(fc.string({ unit: 'binary', maxLength: 300 }), fc.constantFrom('(x64)', ' 1.2.3', '__proto__', 'constructor', '((((((((', '[[[[', 'x'.repeat(1000), ' - en-us', 'v1.2.3-beta'));
    fc.assert(
      fc.property(
        fc.array(
          fc.record({
            displayName: text,
            version: fc.option(text, { nil: null }),
            publisher: fc.option(text, { nil: null }),
            deviceCount: fc.option(fc.oneof(fc.integer(), fc.double()), { nil: null }),
          }),
          { maxLength: 30 },
        ),
        (entries) => {
          const inv = fromInventory(entries, 10);
          expect(inv.candidates.length).toBeLessThanOrEqual(10);
          for (const c of inv.candidates) {
            expect(c.name.trim().length).toBeGreaterThan(0);
            expect(c.name.length).toBeLessThanOrEqual(100);
            if (c.kind === 'product' && c.vendor) expect(c.vendor.length).toBeLessThanOrEqual(100);
          }
        },
      ),
    );
  });

  it('cleans a long hostile name quickly', () => {
    const start = performance.now();
    for (const s of ['1.'.repeat(5000), ' ('.repeat(5000), `${' x64'.repeat(3000)}`, `a${' 1.1'.repeat(3000)}`]) productName(s);
    expect(performance.now() - start).toBeLessThan(200);
  });
});

describe('fitItems', () => {
  const chip = (input: string, ...items: string[]): Chip => ({ input, status: 'resolved', items: items.map((item) => ({ item, label: item, close: item.startsWith('?'), known: true })) });

  it('keeps chips in order until their items would pass the limit, counting shared items once', () => {
    const { kept, over } = fitItems([chip('a', 'p:a/a'), chip('b', '?p:b/1', '?p:b/2'), chip('c', 'p:a/a'), chip('d', 'p:d/d'), chip('e', 'p:e/e')], 4);
    expect(kept.map((c) => c.input)).toEqual(['a', 'b', 'c', 'd']);
    expect(over.map((c) => c.input)).toEqual(['e']);
  });

  it('skips a chip too big to fit but keeps filling with smaller ones', () => {
    const { kept, over } = fitItems([chip('a', 'p:a/a'), chip('big', 'p:b/1', 'p:b/2', 'p:b/3'), chip('c', 'p:c/c')], 2);
    expect(kept.map((c) => c.input)).toEqual(['a', 'c']);
    expect(over.map((c) => c.input)).toEqual(['big']);
  });
});
