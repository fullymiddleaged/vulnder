import { describe, expect, it } from 'vitest';
import type { Chip } from '../src/resolve/catalog';
import { markEsu } from '../src/resolve/esu';

const chip = (input: string, ...items: string[]): Chip => ({ input, status: 'resolved', items: items.map((item) => ({ item, label: item, close: item.startsWith('?'), known: true })) });
const itemsOf = (chips: Chip[]) => chips.map((c) => c.items.map((i) => i.item));

describe('markEsu', () => {
  const chips = [
    chip('Microsoft Windows Server 2012 R2', 'p:microsoft/windows_server_2012_r2@2012_r2', '?p:microsoft/windows_server_2012_r2_server_core_installation@2012_r2'),
    chip('Windows Server 2016', 'p:microsoft/windows_server_2016@2016'),
    chip('Ubuntu 18.04', 'p:canonical/ubuntu_18_04_lts@18.04'),
    chip('nginx 1.24', 'p:f5/nginx@1.24'),
  ];

  it('marks what a sentence about extended support names, and nothing else', () => {
    const text = 'Our DCs run Windows Server 2012 R2 with ESU. File servers are Windows Server 2016.\nUbuntu 18.04 boxes and nginx 1.24.';
    expect(itemsOf(markEsu(chips, text))).toEqual([
      ['p:microsoft/windows_server_2012_r2@2012_r2;esu', '?p:microsoft/windows_server_2012_r2_server_core_installation@2012_r2;esu'],
      ['p:microsoft/windows_server_2016@2016'],
      ['p:canonical/ubuntu_18_04_lts@18.04'],
      ['p:f5/nginx@1.24'],
    ]);
  });

  it('reads Ubuntu Pro, ELS and LTSS, and a dot in a version doesn’t end the sentence', () => {
    expect(itemsOf(markEsu(chips, 'Ubuntu 18.04 on Ubuntu Pro'))[2]).toEqual(['p:canonical/ubuntu_18_04_lts@18.04;esu']);
  });

  it('marks only products it has support dates for', () => {
    expect(itemsOf(markEsu(chips, 'nginx 1.24 with extended support'))[3]).toEqual(['p:f5/nginx@1.24']);
  });

  it('keeps teams and edge tags', () => {
    const teamed = [chip('Windows Server 2012 R2', 'p:microsoft/windows_server_2012_r2@2012_r2;platform;internal')];
    expect(itemsOf(markEsu(teamed, 'Windows Server 2012 R2 (ESU)'))).toEqual([['p:microsoft/windows_server_2012_r2@2012_r2;platform;internal;esu']]);
  });

  it('changes nothing when no sentence mentions extended support', () => {
    expect(markEsu(chips, 'Windows Server 2012 R2 and Ubuntu 18.04')).toBe(chips);
  });

  it('is safe on hostile text', () => {
    const hostile = `${'ESU '.repeat(5000)}\u0000__proto__ ${'.'.repeat(5000)}`;
    expect(() => markEsu(chips, hostile)).not.toThrow();
  });
});
