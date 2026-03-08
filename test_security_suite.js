#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const assert = require('assert');

const root = __dirname;
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');

function testManifestSecurityPermissions() {
  const manifest = JSON.parse(read('manifest.json'));
  const perms = new Set(manifest.permissions || []);
  assert(perms.has('webRequest'), 'manifest missing webRequest permission');
  assert(perms.has('webRequestBlocking'), 'manifest missing webRequestBlocking permission');
  assert(perms.has('tabs'), 'manifest missing tabs permission');
  assert(perms.has('webNavigation'), 'manifest missing webNavigation permission');
}

function testRulesUniqueness() {
  const rules = JSON.parse(read('rules.json'));
  const ids = rules.map((r) => r.id);
  const unique = new Set(ids);
  assert.strictEqual(unique.size, ids.length, 'rules.json contains duplicate rule IDs');
}

function testBlockingGuardPresent() {
  const bg = read('background.js');

  const registrationRe = /webRequest\.onBeforeRequest\.addListener\(\s*mainFrameRequestGuard\s*,\s*MAIN_FRAME_FILTER\s*,\s*\[\s*"blocking"\s*\]\s*\)/m;
  assert(registrationRe.test(bg), 'main-frame blocking guard registration missing or malformed');

  const guardStart = bg.indexOf('const mainFrameRequestGuard = async (details) => {');
  const guardEnd = bg.indexOf('const MAIN_FRAME_FILTER =', guardStart);
  assert(guardStart >= 0 && guardEnd > guardStart, 'mainFrameRequestGuard function boundaries not found');
  const guardBody = bg.slice(guardStart, guardEnd);

  assert(guardBody.includes('return { cancel: true };'), 'mainFrameRequestGuard lacks explicit cancel path');
  assert(guardBody.includes('handleMaliciousUrl('), 'mainFrameRequestGuard lacks malicious redirect handler path');
  assert(bg.includes('const SAFE_BROWSING_ERROR_PATTERNS = ['), 'safe-browsing handoff pattern list missing');
}

function main() {
  testManifestSecurityPermissions();
  testRulesUniqueness();
  testBlockingGuardPresent();
  console.log('test_security_suite.js: all checks passed');
}

main();
