import { describe, expect, it } from 'vitest';
import { nameDrift, type CatalogProduct } from './name-drift';

const row = (key: string, count = 10): CatalogProduct => {
  const [vendor, product] = key.split('/') as [string, string];
  return { key, vendor, product, count };
};

describe('nameDrift', () => {
  it('flags a new spelling of a line’s product, but not what the line keeps out on purpose', () => {
    const drift = nameDrift([
      row('apache_software_foundation/apache_http_server'),
      // A new key under Apache's own spelling, holding the line's name.
      row('apache_software_foundation/apache_http_server_2_4'),
      // RHEL's keep leaves out update-service add-ons; Windows Server is its own line.
      row('red_hat/red_hat_enterprise_linux_9'),
      row('red_hat/red_hat_enterprise_linux_9_4_update_services_for_sap_solutions'),
      row('microsoft/windows_11_version_24h2'),
      row('microsoft/windows_server_2022'),
      // Too small to bother with.
      row('apache_software_foundation/apache_http_server_contrib', 1),
    ]).filter((d) => /^line "(apache|rhel|windows)"/.test(d));
    expect(drift).toEqual(['line "apache": apache_software_foundation/apache_http_server_2_4 (10) shares its name but isn\'t in it']);
  });

  it('flags a line with nothing in the catalog', () => {
    expect(nameDrift([])).toContain('line "crushftp": nothing in the catalog (keys: crushftp/crushftp)');
  });

  it('flags vendor keys that look like one vendor, unless they are already a family', () => {
    const drift = nameDrift([row('zoomcorp/a'), row('acme/a'), row('acme_inc/b'), row('juniper/junos'), row('juniper_networks/junos_os')]).filter((d) => d.startsWith('vendor'));
    expect(drift).toEqual(['vendor "acme" (10) and "acme_inc" (10) may be one vendor']);
  });
});
