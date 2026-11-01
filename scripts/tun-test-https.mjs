// Hosted-runner TLS responder fixture for local TestISP traffic verification.
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:https';
import path from 'node:path';
import { hostedOnly, run } from '../tests/windows/testisp/harness.mjs';

// The harness default of 60 s expired in job 120165918557 on windows-11-arm.
// Apart from the cold powershell.exe start, this call loads the PKI module
// that mounts Cert:, so it needs more room than a plain command. The job
// warms powershell.exe first; this deadline also covers that first load.
const CERTIFICATE_TIMEOUT_MS = 120_000;

export async function localHttps(address) {
  hostedOnly();
  const passphrase = randomBytes(24).toString('hex');
  const started = Date.now();
  const result = await run('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
    path.resolve('scripts/tun-test-certificate.ps1')], {
    timeout: CERTIFICATE_TIMEOUT_MS,
    // Control runs under pwsh. Let Windows PowerShell build its own module path
    // so its Security provider can mount Cert:, rather than inheriting PS7's.
    env: { NETSWITCH_TEST_CERT_PASSWORD: passphrase, PSModulePath: undefined },
  });
  console.log(`TLS certificate ready in ${Date.now() - started} ms`);
  const identity = JSON.parse(result.stdout);
  const ca = `-----BEGIN CERTIFICATE-----\n${identity.cert}\n-----END CERTIFICATE-----\n`;
  const seen = [];
  const events = [];
  let next = 0;
  const sockets = new WeakMap();
  let closing = false;
  function observe(socket) {
    if (sockets.has(socket)) return sockets.get(socket);
    const connection = ++next;
    sockets.set(socket, connection);
    const source = socket.remoteAddress, sourcePort = socket.remotePort;
    const event = (name, extra = {}) => {
      const detail = { at: new Date().toISOString(), connection, source, sourcePort, event: name, ...extra };
      events.push(detail);
      console.log(`TLS responder: ${JSON.stringify(detail)}`);
    };
    event('secureConnection');
    socket.on('end', () => event('peer FIN'));
    socket.on('error', (error) => event('error', { code: error.code, message: error.message }));
    socket.on('close', (hadError) => event('close', { hadError, requestedByTest: closing }));
    return connection;
  }
  const server = createServer({ pfx: Buffer.from(identity.pfx, 'base64'), passphrase }, (req, res) => {
    const observation = { nonce: new URL(req.url, 'https://netswitch.invalid').searchParams.get('nonce'),
      connection: observe(req.socket), source: req.socket.remoteAddress, sourcePort: req.socket.remotePort };
    seen.push(observation);
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(observation));
  });
  server.on('secureConnection', observe);
  server.on('tlsClientError', (error, socket) => {
    console.log(`TLS responder handshake error: ${JSON.stringify({ at: new Date().toISOString(),
      source: socket.remoteAddress, sourcePort: socket.remotePort, code: error.code, message: error.message })}`);
  });
  // The test, not a server idle timeout, decides when the 100 sockets close.
  server.keepAliveTimeout = 180_000;
  server.headersTimeout = 185_000;
  server.listen(0, address);
  await once(server, 'listening');
  return {
    target: { host: '203.0.113.44', port: 443, servername: 'netswitch.invalid', ca },
    address, port: server.address().port, seen, events,
    async close() { closing = true; server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); },
  };
}
