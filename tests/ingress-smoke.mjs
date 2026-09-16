import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { request as httpRequest } from 'node:http';

const [binary, root] = process.argv.slice(2);
assert(binary && root, 'usage: node tests/ingress-smoke.mjs <binary> <engine-root>');
const directory = await mkdtemp(join(tmpdir(), 'cartridge-ingress-'));
const tokenFile = join(directory, 'token');
const token = randomBytes(32).toString('hex');
await writeFile(tokenFile, token, { mode: 0o600 });
const child = spawn(binary, ['engine', 'ingress', 'service-stack', 'api', '--root', root, '--token-file', tokenFile], { windowsHide: true });
let output = '';
let errors = '';
child.stdout.on('data', chunk => { output += chunk; });
child.stderr.on('data', chunk => { errors += chunk; });
let spawnError;
child.on('error', error => { spawnError = error; });
const exited = new Promise(resolve => child.once('close', resolve));
try {
  const deadline = Date.now() + 10000;
  while (!output.includes('\n')) {
    if (spawnError) throw spawnError;
    assert(child.exitCode === null, `gateway exited: ${errors}`);
    assert(Date.now() < deadline, 'gateway startup timed out');
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  const url = output.trim();
  assert.match(url, /^http:\/\/127\.0\.0\.1:\d+$/);
  const request = (path, options = {}) => fetch(url + path, { ...options, signal: AbortSignal.timeout(10000) });
  assert.equal((await request('/health')).status, 401);
  const headers = { Authorization: `Bearer ${token}` };
  assert.equal((await request('/health', { headers: { ...headers, Origin: 'https://example.com' } })).status, 403);
  const wrongHost = await new Promise((resolve, reject) => {
    const req = httpRequest(url + '/health', { headers: { ...headers, Host: 'evil.example' }, timeout: 5000 }, res => {
      res.resume();
      resolve(res.statusCode);
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('host check timed out')));
    req.end();
  });
  assert.equal(wrongHost, 421);
  const response = await request('/health', { headers });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'GET /health');
  const post = await request('/v1/check?ok=true', { method: 'POST', headers, body: 'ping' });
  assert.equal(post.status, 200);
  assert.equal(await post.text(), 'POST /v1/check?ok=true');
  const head = await request('/health', { method: 'HEAD', headers });
  assert.equal(head.status, 200);
  assert.equal(await head.text(), '');
  assert(!output.includes(token) && !errors.includes(token), 'gateway leaked token');
  console.log('authenticated ingress, browser rejection, host fencing, POST and HEAD passed');
} finally {
  child.kill('SIGTERM');
  const timer = setTimeout(() => child.kill('SIGKILL'), 6000);
  await exited;
  clearTimeout(timer);
  await rm(directory, { recursive: true });
}
