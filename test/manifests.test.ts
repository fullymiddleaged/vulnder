import { describe, expect, it } from 'vitest';
import { parseManifest } from '../src/resolve/manifests';
import { parsePurl } from '../src/resolve/manifests/purl';
import { exactCargo, exactSemver, parsePep508 } from '../src/resolve/manifests/versions';
import type { Candidate } from '../src/resolve/types';

const names = (cs: Candidate[]) => cs.map((c) => (c.kind === 'package' ? `${c.ecosystem}:${c.name}@${c.version ?? ''}${c.direct ? '' : ' (t)'}` : `product:${c.vendor ?? ''}/${c.name}@${c.version ?? ''}`));

describe('version helpers', () => {
  it('keeps only exact versions', () => {
    expect(exactSemver('1.2.3')).toBe('1.2.3');
    expect(exactSemver('=1.2.3')).toBe('1.2.3');
    expect(exactSemver('v2.0.0-rc.1')).toBe('2.0.0-rc.1');
    for (const r of ['^1.2.3', '~1.2', '>=1', '1.x', '*', 'latest', 'workspace:*', 'github:foo/bar']) expect(exactSemver(r)).toBeNull();
    expect(exactCargo('=1.0.5')).toBe('1.0.5');
    expect(exactCargo('1.0.5')).toBeNull();
  });

  it('parses PEP 508 requirements', () => {
    expect(parsePep508('Django==4.2.7')).toEqual({ name: 'Django', version: '4.2.7' });
    expect(parsePep508('uvicorn[standard]>=0.30 ; python_version >= "3.9"')).toEqual({ name: 'uvicorn', version: null });
    expect(parsePep508('requests (==2.31.0)')).toEqual({ name: 'requests', version: '2.31.0' });
    expect(parsePep508('numpy==1.*')).toEqual({ name: 'numpy', version: null });
  });
});

describe('package.json', () => {
  it('reads every dependency group, keeping exact versions only', () => {
    const text = JSON.stringify({
      name: 'app',
      dependencies: { next: '14.2.3', react: '^18.3.1', '@angular/core': '17.0.0' },
      devDependencies: { vitest: '~4.1.0' },
    });
    expect(parseManifest(text)).toEqual({
      format: 'package.json',
      candidates: [
        { kind: 'package', ecosystem: 'npm', name: 'next', version: '14.2.3', direct: true },
        { kind: 'package', ecosystem: 'npm', name: 'react', version: null, direct: true },
        { kind: 'package', ecosystem: 'npm', name: '@angular/core', version: '17.0.0', direct: true },
        { kind: 'package', ecosystem: 'npm', name: 'vitest', version: null, direct: true },
      ],
    });
  });
});

describe('package-lock.json', () => {
  it('marks direct dependencies (v3)', () => {
    const text = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'app', dependencies: { next: '^14.2.0' }, devDependencies: { vitest: '^4' } },
        'node_modules/next': { version: '14.2.3' },
        'node_modules/vitest': { version: '4.1.11', dev: true },
        'node_modules/postcss': { version: '8.4.31' },
        'node_modules/next/node_modules/postcss': { version: '8.4.14' },
        'node_modules/linked': { link: true, resolved: '../linked' },
      },
    });
    expect(names(parseManifest(text)!.candidates)).toEqual([
      'npm:next@14.2.3',
      'npm:vitest@4.1.11',
      'npm:postcss@8.4.31 (t)',
      'npm:postcss@8.4.14 (t)',
    ]);
  });

  it('reads lockfile version 1', () => {
    const text = JSON.stringify({
      lockfileVersion: 1,
      dependencies: { express: { version: '4.18.2', dependencies: { qs: { version: '6.11.0' } } } },
    });
    expect(names(parseManifest(text)!.candidates)).toEqual(['npm:express@4.18.2', 'npm:qs@6.11.0 (t)']);
  });
});

describe('Python', () => {
  it('reads requirements.txt', () => {
    const text = '# web\nfastapi==0.115.0\nuvicorn[standard]>=0.30\n-r base.txt\n--hash=sha256:abc\nDjango_REST.framework===3.15.1 ; python_version>"3.8"\n';
    expect(names(parseManifest(text)!.candidates)).toEqual(['PyPI:fastapi@0.115.0', 'PyPI:uvicorn@', 'PyPI:Django_REST.framework@3.15.1']);
  });

  it('does not mistake a word list for requirements', () => {
    expect(parseManifest('redis\nnginx\npostgres')).toBeNull();
    expect(parseManifest('Next.js on Vercel, Postgres 16, Redis, nginx, a couple of Cisco switches')).toBeNull();
  });

  it('uses the file name when given', () => {
    expect(parseManifest('redis\nnginx', 'requirements-dev.txt')).toEqual({
      format: 'requirements.txt',
      candidates: [
        { kind: 'package', ecosystem: 'PyPI', name: 'redis', version: null, direct: true },
        { kind: 'package', ecosystem: 'PyPI', name: 'nginx', version: null, direct: true },
      ],
    });
  });

  it('reads PEP 621 and Poetry pyproject.toml', () => {
    const text = `[project]
name = "svc"
dependencies = ["fastapi==0.115.0", "httpx>=0.27"]
[project.optional-dependencies]
test = ["pytest==8.3.3"]
[tool.poetry.dependencies]
python = "^3.12"
sqlalchemy = "2.0.35"
pydantic = { version = "^2.9" }
[tool.poetry.group.dev.dependencies]
ruff = "==0.6.9"
`;
    expect(names(parseManifest(text)!.candidates)).toEqual([
      'PyPI:fastapi@0.115.0',
      'PyPI:httpx@',
      'PyPI:pytest@8.3.3',
      'PyPI:sqlalchemy@',
      'PyPI:pydantic@',
      'PyPI:ruff@0.6.9',
    ]);
  });
});

describe('go.mod', () => {
  it('reads require blocks and single requires, marking indirect ones', () => {
    const text = `module example.com/app

go 1.23

require github.com/gin-gonic/gin v1.10.0

require (
\tgolang.org/x/net v0.30.0 // indirect
\tgithub.com/containers/podman/v5 v5.6.0
)
`;
    expect(names(parseManifest(text)!.candidates)).toEqual([
      'Go:github.com/gin-gonic/gin@v1.10.0',
      'Go:golang.org/x/net@v0.30.0 (t)',
      'Go:github.com/containers/podman/v5@v5.6.0',
    ]);
  });
});

describe('Cargo.toml', () => {
  it('reads dependency tables and renamed packages', () => {
    const text = `[package]
name = "svc"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "=1.40.0", features = ["full"] }
web = { package = "actix-web", version = "4" }

[dev-dependencies]
proptest = "1"
`;
    expect(names(parseManifest(text)!.candidates)).toEqual(['crates.io:serde@', 'crates.io:tokio@1.40.0', 'crates.io:actix-web@', 'crates.io:proptest@']);
  });
});

describe('pom.xml', () => {
  it('reads dependencies and resolves properties', () => {
    const text = `<?xml version="1.0"?>
<project>
  <groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
  <properties><log4j.version>2.17.1</log4j.version></properties>
  <dependencies>
    <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>\${log4j.version}</version></dependency>
    <!-- <dependency><groupId>x</groupId><artifactId>commented</artifactId></dependency> -->
    <dependency><groupId>org.springframework</groupId><artifactId>spring-core</artifactId><version>[6.0,7.0)</version></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId></dependency>
  </dependencies>
</project>`;
    expect(names(parseManifest(text)!.candidates)).toEqual([
      'Maven:org.apache.logging.log4j:log4j-core@2.17.1',
      'Maven:org.springframework:spring-core@',
      'Maven:junit:junit@',
    ]);
  });

  it('takes the project version from outside <parent> and <dependencies>, trimming element text', () => {
    const text = `<project>
  <parent><groupId>com.example</groupId><artifactId>parent</artifactId><version>9.9</version></parent>
  <version>
    2.0.0
  </version>
  <dependencies>
    <dependency><groupId> com.example </groupId><artifactId>lib</artifactId><version>\${project.version}</version></dependency>
    <dependency><groupId>com.example</groupId><artifactId>other</artifactId><version>3.1</version></dependency>
  </dependencies>
</project>`;
    expect(names(parseManifest(text)!.candidates)).toEqual(['Maven:com.example:lib@2.0.0', 'Maven:com.example:other@3.1']);
  });
});

describe('Gemfile.lock', () => {
  it('reads gem specs and marks direct dependencies', () => {
    const text = `GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.1.3)
      rack (~> 3.0)
    nokogiri (1.16.2-x86_64-linux)
    rack (3.0.9)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  actionpack
  nokogiri (~> 1.16)

BUNDLED WITH
   2.5.6
`;
    expect(names(parseManifest(text)!.candidates)).toEqual(['RubyGems:actionpack@7.1.3', 'RubyGems:nokogiri@1.16.2', 'RubyGems:rack@3.0.9 (t)']);
  });
});

describe('composer.json', () => {
  it('skips platform requirements', () => {
    const text = JSON.stringify({ require: { php: '>=8.2', 'ext-json': '*', 'laravel/framework': '^11.0', 'monolog/monolog': '3.7.0' }, 'require-dev': { 'phpunit/phpunit': '^11' } });
    expect(names(parseManifest(text)!.candidates)).toEqual(['Packagist:laravel/framework@', 'Packagist:monolog/monolog@3.7.0', 'Packagist:phpunit/phpunit@']);
  });
});

describe('Dockerfile', () => {
  it('names base images, skipping build stages, scratch and variables', () => {
    const text = `ARG NODE=20
# syntax=docker/dockerfile:1
FROM --platform=linux/amd64 node:20.11-alpine AS build
FROM build AS test
FROM nginx:1.25.3@sha256:abcdef
FROM ghcr.io/acme/tool:v2
FROM bitnami/redis:7.2
FROM library/postgres:16
FROM \${BASE}
FROM scratch
`;
    expect(names(parseManifest(text)!.candidates)).toEqual([
      'product:/node@20.11',
      'product:/nginx@1.25.3',
      'product:acme/tool@',
      'product:bitnami/redis@7.2',
      'product:/postgres@16',
    ]);
  });
});

describe('SBOMs', () => {
  it('reads CycloneDX components by purl, including nested ones', () => {
    const text = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      components: [
        { type: 'library', name: 'core', purl: 'pkg:npm/%40angular/core@17.0.0', components: [{ purl: 'pkg:pypi/django@4.2.7' }] },
        { type: 'library', purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1' },
        { type: 'operating-system', purl: 'pkg:deb/debian/openssl@3.0.11' },
      ],
    });
    expect(names(parseManifest(text)!.candidates)).toEqual(['npm:@angular/core@17.0.0', 'PyPI:django@4.2.7', 'Maven:org.apache.logging.log4j:log4j-core@2.17.1']);
  });

  it('reads SPDX packages by purl', () => {
    const text = JSON.stringify({
      spdxVersion: 'SPDX-2.3',
      packages: [{ name: 'gin', externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:golang/github.com/gin-gonic/gin@v1.10.0' }] }],
    });
    expect(names(parseManifest(text)!.candidates)).toEqual(['Go:github.com/gin-gonic/gin@v1.10.0']);
  });

  it('parses purls', () => {
    expect(parsePurl('pkg:cargo/serde@1.0.210')).toEqual({ ecosystem: 'crates.io', name: 'serde', version: '1.0.210' });
    expect(parsePurl('pkg:composer/laravel/framework@v11.0.0?foo=bar')).toEqual({ ecosystem: 'Packagist', name: 'laravel/framework', version: 'v11.0.0' });
    expect(parsePurl('pkg:rpm/fedora/curl@7.50')).toBeNull();
    expect(parsePurl('not a purl')).toBeNull();
  });
});

describe('detection', () => {
  it('treats free text as no manifest', () => {
    expect(parseManifest('We run Kubernetes with some Cisco switches.')).toBeNull();
    expect(parseManifest('{"not": "a manifest"}')).toBeNull();
  });

  it('falls through when the named parser fails', () => {
    expect(parseManifest('this is not json', 'package.json')).toBeNull();
  });

  // The server parses pasted text up to 200,000 characters. Each of these took
  // from 0.2 s to over 3 minutes before its regex was made linear; workerd's
  // clock doesn't advance mid-test, so the test timeout is the check.
  it('parses hostile input in linear time, by content and by every file name', { timeout: 10_000 }, () => {
    const fill = (unit: string, head = '', tail = '') => head + unit.repeat(Math.floor((200_000 - head.length - tail.length) / unit.length)) + tail;
    const hostile = [
      fill(' ', 'a', '#'),
      fill('\t', 'a[x]', '#'),
      fill('\n', 'a==1\n'),
      fill('<!--', '<project><dependency>'),
      fill('<dependency>', '<project>'),
      fill('<dependencies>', '<project><dependency>'),
      fill('<properties><x>', '<project><dependency>'),
      fill('<parent>', '<project><dependency>'),
      fill(' ', '<project><dependency><groupId>'),
    ];
    const filenames = [undefined, 'package-lock.json', 'package.json', 'requirements.txt', 'pyproject.toml', 'go.mod', 'Cargo.toml', 'pom.xml', 'Gemfile.lock', 'composer.json', 'Dockerfile', 'a.cdx.json', 'a.spdx.json'];
    for (const text of hostile) for (const filename of filenames) expect(() => parseManifest(text, filename)).not.toThrow();
  });
});
