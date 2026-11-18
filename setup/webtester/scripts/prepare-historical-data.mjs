#!/usr/bin/env node
/**
 * Data Preparation Script for PS-028 Historical Evidence Explorer
 *
 * Deterministically resolves repository root, reads and cryptographically validates
 * lab/derived/phase-e/demo_bundle.json against its provenance sidecar, and
 * copies the verified static assets into setup/webtester/public/data/.
 *
 * Barred from modifying the source bundle or fabricating mock data.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function resolveRepoRoot(startDir) {
  let curr = path.resolve(startDir);
  while (true) {
    const candidateBundle = path.join(curr, 'lab', 'derived', 'phase-e', 'demo_bundle.json');
    const candidateProv = path.join(curr, 'lab', 'derived', 'phase-e', 'demo_bundle.json.provenance.json');
    if (fs.existsSync(candidateBundle) && fs.existsSync(candidateProv)) {
      return curr;
    }
    const parent = path.dirname(curr);
    if (parent === curr) {
      break;
    }
    curr = parent;
  }
  throw new Error(
    `Failed to locate repository root containing lab/derived/phase-e/demo_bundle.json from ${startDir}`
  );
}

export function prepareHistoricalData() {
  const repoRoot = resolveRepoRoot(__dirname);
  const sourceBundlePath = path.join(repoRoot, 'lab', 'derived', 'phase-e', 'demo_bundle.json');
  const sourceProvPath = path.join(repoRoot, 'lab', 'derived', 'phase-e', 'demo_bundle.json.provenance.json');

  if (!fs.existsSync(sourceBundlePath)) {
    throw new Error(`Mandatory historical demo bundle missing at ${sourceBundlePath}`);
  }
  if (!fs.existsSync(sourceProvPath)) {
    throw new Error(`Mandatory demo bundle provenance sidecar missing at ${sourceProvPath}`);
  }

  // Read raw bytes to ensure exact bit-for-bit digest validation
  const rawBundleBytes = fs.readFileSync(sourceBundlePath);
  const rawProvText = fs.readFileSync(sourceProvPath, 'utf8');

  // Cryptographic SHA-256 verification
  const computedSha256 = crypto.createHash('sha256').update(rawBundleBytes).digest('hex');
  const provenance = JSON.parse(rawProvText);

  if (!provenance.output_bundle_sha256) {
    throw new Error(`Provenance sidecar at ${sourceProvPath} missing 'output_bundle_sha256' field`);
  }

  if (computedSha256 !== provenance.output_bundle_sha256) {
    throw new Error(
      `Provenance validation FAILURE: computed SHA-256 (${computedSha256}) does not match sidecar (${provenance.output_bundle_sha256})`
    );
  }

  // Schema identity verification
  const bundle = JSON.parse(rawBundleBytes.toString('utf8'));
  if (bundle.bundle_schema_version !== '1.0.0') {
    throw new Error(`Unexpected bundle_schema_version: ${bundle.bundle_schema_version} (expected 1.0.0)`);
  }
  if (bundle.campaign_id !== 'ps028-a10-live-20261030-01') {
    throw new Error(`Unexpected campaign_id: ${bundle.campaign_id} (expected ps028-a10-live-20261030-01)`);
  }
  if (bundle.evidence_type !== 'HISTORICAL_LIVE') {
    throw new Error(`Unexpected evidence_type: ${bundle.evidence_type} (expected HISTORICAL_LIVE)`);
  }

  const targetDir = path.resolve(__dirname, '..', 'public', 'data');
  fs.mkdirSync(targetDir, { recursive: true });

  const targetBundlePath = path.join(targetDir, 'demo_bundle.json');
  const targetProvPath = path.join(targetDir, 'demo_bundle.json.provenance.json');

  fs.writeFileSync(targetBundlePath, rawBundleBytes);
  fs.writeFileSync(targetProvPath, rawProvText, 'utf8');

  console.log('================================================================================');
  console.log('[OK] Historical demo bundle verified and staged for WebTester frontend:');
  console.log(`  Source:      ${sourceBundlePath}`);
  console.log(`  Target:      ${targetBundlePath}`);
  console.log(`  Bundle Size: ${(rawBundleBytes.length / (1024 * 1024)).toFixed(2)} MB`);
  console.log(`  SHA-256:     ${computedSha256}`);
  console.log(`  Provenance:  VERIFIED (${provenance.generator_script} @ ${provenance.generator_commit.slice(0, 10)})`);
  console.log(`  Trials:      ${bundle.trials?.length ?? 0} valid live trials, ${bundle.exclusions?.length ?? 0} excluded attempts`);
  console.log('================================================================================');

  return {
    repoRoot,
    targetBundlePath,
    targetProvPath,
    computedSha256,
    validTrials: bundle.trials?.length ?? 0,
    excludedAttempts: bundle.exclusions?.length ?? 0,
  };
}

if (process.argv[1] === __filename) {
  try {
    prepareHistoricalData();
  } catch (err) {
    console.error(`[ERROR] Historical data preparation failed: ${err.message}`);
    process.exit(1);
  }
}
