import { describe, expect, it } from 'vitest';
import { classifyProfile, rankByProfile, rulesClassifier, segmentsOf, type ProfileSignals } from '../src/resolve/profile';

const none: ProfileSignals = { products: [], vendors: [], directPackages: 0, modelHint: null };

describe('segmentsOf', () => {
  it('prefers a specific entry over the vendor catch-all', () => {
    expect(segmentsOf('cisco', 'cisco_small_business_rv_series_routers')).toEqual(['smb', 'home']);
    expect(segmentsOf('cisco', 'cisco_ios_xe_software')).toEqual(['enterprise']);
    expect(segmentsOf('microsoft', 'azure_key_vault')).toEqual(['cloud']);
  });

  it('returns nothing for untagged products', () => {
    expect(segmentsOf('postgresql', 'postgresql')).toEqual([]);
    expect(segmentsOf('microsoft', 'windows')).toEqual([]);
  });
});

describe('rulesClassifier', () => {
  it('makes no guess without evidence or on a tie', () => {
    expect(rulesClassifier(none)).toEqual({ profile: null, confidence: 0 });
    expect(
      rulesClassifier({ ...none, products: [{ vendor: 'netgear', product: 'r7000' }, { vendor: 'aws', product: 'aws_load_balancer_controller' }] }),
    ).toEqual({ profile: null, confidence: 0 });
  });

  it('calls a lockfile a developer stack', () => {
    expect(rulesClassifier({ ...none, directPackages: 40 })).toEqual({ profile: 'developer', confidence: 1 });
  });

  it('reads home gear from exact products and vague vendors', () => {
    const guess = rulesClassifier({
      ...none,
      products: [{ vendor: 'tp_link', product: 'archer_ax21' }, { vendor: 'synology', product: 'diskstation_manager' }],
      vendors: ['netgear'],
    });
    // home: 1 + 0.5 + 0.5 = 2; smb: 0.5 → 0.8 agreement × 2.5/3 evidence.
    expect(guess).toEqual({ profile: 'home', confidence: 0.67 });
  });

  it('scales confidence down when there is little evidence', () => {
    expect(rulesClassifier({ ...none, vendors: ['cisco'] })).toEqual({ profile: 'enterprise', confidence: 0.17 });
  });

  it('lets the model hint outweigh a single product', () => {
    const guess = rulesClassifier({ ...none, products: [{ vendor: 'cisco', product: 'ios_xe' }], modelHint: 'home' });
    expect(guess.profile).toBe('home');
    expect(guess.confidence).toBe(0.75);
  });

  it('can be swapped for another classifier', async () => {
    const guess = await classifyProfile(none, async () => ({ profile: 'cloud', confidence: 0.9 }));
    expect(guess).toEqual({ profile: 'cloud', confidence: 0.9 });
  });
});

describe('rankByProfile', () => {
  const key = (s: string) => {
    const [vendor, product] = s.split('/');
    return vendor && product ? { vendor, product } : null;
  };

  it('puts fitting items first, untagged next, other profiles last, keeping order within each', () => {
    const items = ['cisco/ios_xe', 'postgresql/postgresql', 'cisco/small_business_switches', 'npm-package', 'cisco/nx_os', 'cisco/rv340_firmware'];
    expect(rankByProfile(items, 'home', key)).toEqual([
      'cisco/small_business_switches',
      'cisco/rv340_firmware',
      'postgresql/postgresql',
      'npm-package',
      'cisco/ios_xe',
      'cisco/nx_os',
    ]);
  });

  it('never drops or adds items', () => {
    const items = ['cisco/ios_xe', 'cisco/nx_os'];
    expect(rankByProfile(items, 'enterprise', key)).toEqual(items);
    expect(rankByProfile([], 'home', key)).toEqual([]);
  });
});
