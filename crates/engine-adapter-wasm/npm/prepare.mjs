#!/usr/bin/env node
/**
 * Composes the publishable npm package from the wasm-pack build.
 *
 * wasm-pack generates the package from the crate's Cargo.toml — the
 * file list, the entry points, the side-effects — but the name is the
 * crate's (`engine-adapter-wasm`) and the npm metadata (the
 * @sirosfoundation scope, the keywords, the publish config) belongs
 * to the overlay in npm/package.template.json. This script merges the
 * two: the generated package.json owns what wasm-pack knows (files,
 * main, types, sideEffects, the module graph), the template owns the
 * npm identity, and the version comes from the release tag (the same
 * version the XCFramework/AAR release carries).
 *
 * Usage:
 *   node npm/prepare.mjs <pkg-dir> [--version <semver>] [--repo-root <dir>]
 *
 * The <pkg-dir> is the wasm-pack output (target/npm-pkg). The version
 * defaults to the crate's (from the generated package.json).
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

function arg(name, fallback = undefined) {
  const index = process.argv.indexOf(name);
  return index !== -1 && index + 1 < process.argv.length
    ? process.argv[index + 1]
    : fallback;
}

const pkgDir = arg('--pkg', process.argv[2]);
if (!pkgDir || !fs.existsSync(path.join(pkgDir, 'package.json'))) {
  console.error('usage: node npm/prepare.mjs <pkg-dir> [--version <semver>]');
  console.error('       <pkg-dir> is the wasm-pack output directory');
  process.exit(1);
}
const version = arg('--version');
const repoRoot = path.resolve(arg('--repo-root', path.join(here, '..', '..', '..')));

// The generated package: the wasm-pack facts.
const generated = JSON.parse(
  fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8')
);

// The npm identity overlay.
const template = JSON.parse(
  fs.readFileSync(path.join(here, 'package.template.json'), 'utf8')
);

// Sanity: the build's entry points exist beside the package.json.
const entry = generated.main;
if (!entry || !fs.existsSync(path.join(pkgDir, entry))) {
  console.error(`the generated entry point ${entry} is missing from ${pkgDir}`);
  process.exit(1);
}
const wasm = generated.files.find((f) => f.endsWith('.wasm'));
if (!wasm || !fs.existsSync(path.join(pkgDir, wasm))) {
  console.error('the wasm binary is missing from the package');
  process.exit(1);
}

// The merge: the template's identity, the generated's build facts.
const pkg = {
  ...template,
  type: 'module',
  collaborators: generated.collaborators,
  main: generated.main,
  types: generated.types,
  files: generated.files,
  sideEffects: generated.sideEffects,
  version: version || generated.version,
};

// The snippets wasm-pack adds for multi-crate builds: referenced by
// the glue's sideEffects, published with the rest.
if (fs.existsSync(path.join(pkgDir, 'snippets'))) {
  pkg.files.push('snippets/*');
}

// The npm package page: the README and the license ride along.
fs.copyFileSync(path.join(here, 'README.md'), path.join(pkgDir, 'README.md'));
fs.copyFileSync(
  path.join(repoRoot, 'LICENSE'),
  path.join(pkgDir, 'LICENSE')
);

fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify(pkg, null, 2) + '\n');
console.log(`prepared ${pkg.name}@${pkg.version} in ${pkgDir}`);
console.log(`  files: ${pkg.files.join(', ')}`);
