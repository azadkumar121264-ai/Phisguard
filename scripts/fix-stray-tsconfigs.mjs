#!/usr/bin/env node
/**
 * Removes the unresolvable `"extends": "@ljharb/tsconfig"` entry from the
 * tsconfig.json files that runtime dependencies ship inside node_modules
 * (math-intrinsics, get-intrinsic, gopd, hasown, side-channel, ...).
 *
 * Why the entry is broken
 *   `@ljharb/tsconfig` is only a *dev*Dependency of those packages, so it is not
 *   installed for consumers. TypeScript therefore reports, for every shipped config:
 *       File '@ljharb/tsconfig' not found.   (TS6053)
 *   and bundlers that read tsconfig.json (e.g. esbuild-loader via get-tsconfig) fail.
 *   Upstream report (closed as "not planned"): https://github.com/ljharb/tsconfig/issues/2
 *
 * Why we do not simply `npm i -D @ljharb/tsconfig`
 *   That config sets allowJs/checkJs/strict/maxNodeModuleJsDepth, so TypeScript
 *   starts type-checking the dependencies' own JavaScript and reports hundreds of
 *   new errors *inside* node_modules (math-intrinsics, object-inspect, ...).
 *   Dropping the dangling `extends` keeps each config self-contained and error free.
 *
 * Usage
 *   node scripts/fix-stray-tsconfigs.mjs
 *   (also wired up as the workspace `postinstall` script, so `npm install` re-applies it)
 */

import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** matches a whole `"extends": "@ljharb/tsconfig",` line, tab- or space-indented, LF or CRLF */
const DANGLING_EXTENDS_LINE = /^[ \t]*"extends"[ \t]*:[ \t]*"@ljharb\/tsconfig"[ \t]*,?[ \t]*\r?\n?/gm;
/** matches the same property when the config is written on a single line */
const DANGLING_EXTENDS_INLINE = /"extends"[ \t]*:[ \t]*"@ljharb\/tsconfig"[ \t]*,?/g;

const workspaceRoot = dirname(dirname(fileURLToPath(import.meta.url)));

/** node_modules trees of the workspace root and of every sub-project (frontend, Backend, ...) */
function findNodeModulesDirs() {
	const found = [join(workspaceRoot, 'node_modules')];
	for (const entry of readdirSync(workspaceRoot, { withFileTypes: true })) {
		if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules' && entry.name !== 'scripts') {
			found.push(join(workspaceRoot, entry.name, 'node_modules'));
		}
	}
	return found.filter(existsSync);
}

/** every installed package directory, scoped packages included */
function* installedPackages(nodeModules) {
	for (const entry of readdirSync(nodeModules, { withFileTypes: true })) {
		if (!entry.isDirectory() || entry.name.startsWith('.')) continue;
		const dir = join(nodeModules, entry.name);
		if (entry.name.startsWith('@')) {
			for (const scoped of readdirSync(dir, { withFileTypes: true })) {
				if (scoped.isDirectory()) yield join(dir, scoped.name);
			}
		} else {
			yield dir;
		}
	}
}

/** @returns {boolean} true when the config was rewritten */
function fixConfig(configPath) {
	const original = readFileSync(configPath, 'utf8');
	if (!original.includes('@ljharb/tsconfig')) return false;

	let patched = original.replace(DANGLING_EXTENDS_LINE, '').replace(DANGLING_EXTENDS_INLINE, '');
	if (patched.includes('@ljharb/tsconfig')) {
		console.warn(`  ! could not rewrite ${configPath}, left untouched`);
		return false;
	}
	// collapse a config that is now empty: { } -> {}
	if (/^\s*\{\s*\}\s*$/.test(patched)) patched = '{}\n';

	writeFileSync(configPath, patched);
	console.log(`  fixed ${configPath}`);
	return true;
}

let fixedCount = 0;
try {
	for (const nodeModules of findNodeModulesDirs()) {
		for (const packageDir of installedPackages(nodeModules)) {
			const configPath = join(packageDir, 'tsconfig.json');
			if (!existsSync(configPath)) continue;
			try {
				if (fixConfig(configPath)) fixedCount += 1;
			} catch (error) {
				console.warn(`  ! skipped ${configPath}: ${error.message}`);
			}
		}
	}
	console.log(`fix-stray-tsconfigs: repaired ${fixedCount} dangling "@ljharb/tsconfig" reference(s)`);
} catch (error) {
	// never break `npm install` because of a cosmetic node_modules patch
	console.warn(`fix-stray-tsconfigs: skipped (${error.message})`);
}
