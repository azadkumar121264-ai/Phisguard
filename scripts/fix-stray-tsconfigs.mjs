#!/usr/bin/env node
/**
 * Removes the tsconfig.json files that runtime dependencies ship inside
 * node_modules even though nobody but their own maintainer can use them.
 *
 * The problem
 *   Packages published by ljharb (math-intrinsics, get-intrinsic, gopd, hasown,
 *   side-channel, ...) ship a tsconfig.json that starts with
 *       { "extends": "@ljharb/tsconfig", ... }
 *   while `@ljharb/tsconfig` is only a *dev*Dependency of those packages, so it is
 *   never installed for consumers. TypeScript then reports, for every shipped config:
 *       File '@ljharb/tsconfig' not found.   (TS6053)
 *   Bundlers that read tsconfig.json (esbuild-loader via get-tsconfig) fail as well.
 *   Upstream report, closed as "not planned": https://github.com/ljharb/tsconfig/issues/2
 *
 * Why we delete instead of repairing
 *   Installing the missing base (npm i -D @ljharb/tsconfig) makes TypeScript apply
 *   that strict shared config - allowJs/checkJs/strict/maxNodeModuleJsDepth - and
 *   type-check the dependencies' own JavaScript: hundreds of new errors.
 *   Merely deleting the dangling `extends` is not enough either: those configs are
 *   only complete *with* the missing base, so their remaining options (target: es5
 *   without lib, ignoreDeprecations, module resolution) then emit new errors such as
 *   TS2550 inside <package>/isNaN.d.ts.
 *   The config is meaningless to consumers, so removing it is the clean fix:
 *   no config means no project, which means no diagnostics.
 *
 * Usage
 *   node scripts/fix-stray-tsconfigs.mjs
 *   (also wired up as the workspace `postinstall` script, so `npm install` re-applies it)
 */

import { existsSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** the dev-only base these packages extend */
const MISSING_BASE = '@ljharb/tsconfig';
/** a config that still points at it directly */
const DANGLING_EXTENDS = /"extends"\s*:\s*"@ljharb\/tsconfig"/;

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

/** does this package ship a config that can only work with the missing dev-only base? */
function shipsUnusableConfig(packageDir) {
	const manifest = join(packageDir, 'package.json');
	if (existsSync(manifest)) {
		try {
			const pkg = JSON.parse(readFileSync(manifest, 'utf8'));
			if (pkg.devDependencies && MISSING_BASE in pkg.devDependencies) return true;
		} catch {
			// unreadable manifest - fall back to inspecting the config itself
		}
	}
	const config = join(packageDir, 'tsconfig.json');
	if (!existsSync(config)) return false;
	try {
		return DANGLING_EXTENDS.test(readFileSync(config, 'utf8'));
	} catch {
		return false;
	}
}

let removed = 0;
try {
	for (const nodeModules of findNodeModulesDirs()) {
		for (const packageDir of installedPackages(nodeModules)) {
			const config = join(packageDir, 'tsconfig.json');
			if (!existsSync(config) || !shipsUnusableConfig(packageDir)) continue;
			try {
				rmSync(config);
				removed += 1;
				console.log(`  removed ${config}`);
			} catch (error) {
				console.warn(`  ! could not remove ${config}: ${error.message}`);
			}
		}
	}
	console.log(`fix-stray-tsconfigs: removed ${removed} unusable node_modules tsconfig.json file(s)`);
} catch (error) {
	// never break `npm install` because of a cosmetic node_modules cleanup
	console.warn(`fix-stray-tsconfigs: skipped (${error.message})`);
}
