import assert from 'node:assert/strict'
import { test } from 'node:test'

import { assertPublicHost, normalizeTarget, TargetError } from '../src/safety.js'

test('adds https:// when no scheme is given', () => {
  assert.equal(normalizeTarget('example.com').toString(), 'https://example.com/')
})

test('rejects blank input', () => {
  assert.throws(() => normalizeTarget('   '), TargetError)
})

test('rejects non-http schemes', () => {
  assert.throws(() => normalizeTarget('ftp://example.com'), TargetError)
  assert.throws(() => normalizeTarget('javascript:alert(1)'), TargetError)
})

test('requires a dotted domain', () => {
  assert.throws(() => normalizeTarget('http://localhost'), TargetError)
})

test('strips credentials from the URL', () => {
  const u = normalizeTarget('https://user:pass@example.com/path')
  assert.equal(u.username, '')
  assert.equal(u.password, '')
})

test('refuses loopback and private IP targets (SSRF guard)', async () => {
  await assert.rejects(assertPublicHost('127.0.0.1'), TargetError)
  await assert.rejects(assertPublicHost('10.0.0.5'), TargetError)
  await assert.rejects(assertPublicHost('192.168.1.1'), TargetError)
  await assert.rejects(assertPublicHost('169.254.169.254'), TargetError) // cloud metadata
  await assert.rejects(assertPublicHost('172.16.5.4'), TargetError)
  await assert.rejects(assertPublicHost('::1'), TargetError)
})

test('allows a public IP', async () => {
  const ips = await assertPublicHost('8.8.8.8')
  assert.deepEqual(ips, ['8.8.8.8'])
})
