import dns from 'node:dns'
import http from 'node:http'
import https from 'node:https'
import { AddressInfo, createServer as createTcpServer, isIP, Server as TcpServer } from 'node:net'
import tls from 'node:tls'
import axios from 'axios'
import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import Sinon from 'sinon'
import sinonChai from 'sinon-chai'

chai.use(chaiAsPromised)
chai.use(sinonChai)

import {
  extractNip05FromEvent,
  isDomainAllowed,
  parseNip05Identifier,
  verifyNip05Identifier,
} from '../../../src/utils/nip05'
import { Event } from '../../../src/@types/event'
import { EventKinds } from '../../../src/constants/base'

const { expect } = chai

const PUBKEY_A = 'a'.repeat(64)
const PUBKEY_B = 'b'.repeat(64)
const SIG_C = 'c'.repeat(128)
const ID_A = PUBKEY_A

function makeEvent(kind: number, content: string): Event {
  return {
    id: ID_A,
    pubkey: PUBKEY_B,
    created_at: 1234567890,
    kind,
    tags: [],
    content,
    sig: SIG_C,
  }
}

describe('NIP-05 utils', () => {
  describe('parseNip05Identifier', () => {
    it('returns parsed identifier for valid input', () => {
      const result = parseNip05Identifier('user@example.com')
      expect(result).to.deep.equal({ localPart: 'user', domain: 'example.com' })
    })

    it('handles underscores in local part', () => {
      const result = parseNip05Identifier('_@example.com')
      expect(result).to.deep.equal({ localPart: '_', domain: 'example.com' })
    })

    it('lowercases domain and local part', () => {
      const result = parseNip05Identifier('User@Example.COM')
      expect(result).to.deep.equal({ localPart: 'user', domain: 'example.com' })
    })

    it('handles subdomains', () => {
      const result = parseNip05Identifier('alice@relay.example.co.uk')
      expect(result).to.deep.equal({ localPart: 'alice', domain: 'relay.example.co.uk' })
    })

    it('returns undefined for empty string', () => {
      expect(parseNip05Identifier('')).to.be.undefined
    })

    it('returns undefined for null input', () => {
      expect(parseNip05Identifier(null as any)).to.be.undefined
    })

    it('returns undefined for non-string input', () => {
      expect(parseNip05Identifier(123 as any)).to.be.undefined
    })

    it('returns undefined for missing @', () => {
      expect(parseNip05Identifier('userexample.com')).to.be.undefined
    })

    it('returns undefined for missing local part', () => {
      expect(parseNip05Identifier('@example.com')).to.be.undefined
    })

    it('returns undefined for missing domain', () => {
      expect(parseNip05Identifier('user@')).to.be.undefined
    })

    it('returns undefined for invalid domain', () => {
      expect(parseNip05Identifier('user@.com')).to.be.undefined
    })

    it('returns undefined for domain without TLD', () => {
      expect(parseNip05Identifier('user@localhost')).to.be.undefined
    })
  })

  describe('extractNip05FromEvent', () => {
    it('extracts nip05 from kind 0 event', () => {
      expect(extractNip05FromEvent(
        makeEvent(EventKinds.SET_METADATA, JSON.stringify({ name: 'alice', nip05: 'alice@example.com' })),
      )).to.equal('alice@example.com')
    })

    it('returns undefined for non-kind-0 event', () => {
      expect(extractNip05FromEvent(
        makeEvent(EventKinds.TEXT_NOTE, JSON.stringify({ nip05: 'alice@example.com' })),
      )).to.be.undefined
    })

    it('returns undefined when nip05 is not in content', () => {
      expect(extractNip05FromEvent(
        makeEvent(EventKinds.SET_METADATA, JSON.stringify({ name: 'alice' })),
      )).to.be.undefined
    })

    it('returns undefined for invalid JSON content', () => {
      expect(extractNip05FromEvent(
        makeEvent(EventKinds.SET_METADATA, 'not json'),
      )).to.be.undefined
    })

    it('returns undefined when nip05 is empty string', () => {
      expect(extractNip05FromEvent(
        makeEvent(EventKinds.SET_METADATA, JSON.stringify({ nip05: '' })),
      )).to.be.undefined
    })

    it('returns undefined when nip05 is not a string', () => {
      expect(extractNip05FromEvent(
        makeEvent(EventKinds.SET_METADATA, JSON.stringify({ nip05: 42 })),
      )).to.be.undefined
    })
  })

  describe('isDomainAllowed', () => {
    it('returns true with no whitelist or blacklist', () => {
      expect(isDomainAllowed('example.com')).to.be.true
    })

    it('returns true with empty whitelist and blacklist', () => {
      expect(isDomainAllowed('example.com', [], [])).to.be.true
    })

    it('returns true if domain is in whitelist', () => {
      expect(isDomainAllowed('example.com', ['example.com'])).to.be.true
    })

    it('returns false if domain is not in whitelist', () => {
      expect(isDomainAllowed('other.com', ['example.com'])).to.be.false
    })

    it('returns false if domain is in blacklist', () => {
      expect(isDomainAllowed('spam.com', undefined, ['spam.com'])).to.be.false
    })

    it('returns true if domain is not in blacklist', () => {
      expect(isDomainAllowed('example.com', undefined, ['spam.com'])).to.be.true
    })

    it('is case-insensitive', () => {
      expect(isDomainAllowed('Example.COM', ['example.com'])).to.be.true
      expect(isDomainAllowed('SPAM.com', undefined, ['spam.COM'])).to.be.false
    })

    it('blacklist takes precedence over whitelist', () => {
      expect(isDomainAllowed('example.com', ['example.com'], ['example.com'])).to.be.false
    })
  })

  describe('verifyNip05Identifier', () => {
    let axiosGetStub: Sinon.SinonStub
    const pubkey = PUBKEY_A

    before(() => {
      axiosGetStub = Sinon.stub(axios, 'get')
    })

    afterEach(() => {
      axiosGetStub.reset()
    })

    after(() => {
      axiosGetStub.restore()
    })

    it('returns invalid for unparseable identifier (no network call)', async () => {
      const outcome = await verifyNip05Identifier('not-an-identifier', pubkey)
      expect(outcome).to.deep.equal({ status: 'invalid', reason: 'unparseable NIP-05 identifier' })
      expect(axiosGetStub).not.to.have.been.called
    })

    it('sends request with capped redirects and body sizes', async () => {
      axiosGetStub.resolves({ data: { names: { alice: pubkey } } })

      await verifyNip05Identifier('alice@example.com', pubkey)

      const config = axiosGetStub.firstCall.args[1]
      expect(config.maxRedirects).to.equal(1)
      expect(config.maxContentLength)
        .to.be.a('number')
        .and.to.be.at.most(64 * 1024)
      expect(config.maxBodyLength)
        .to.be.a('number')
        .and.to.be.at.most(64 * 1024)
      expect(config.validateStatus(200)).to.be.true
      expect(config.validateStatus(301)).to.be.false
      expect(typeof config.beforeRedirect).to.equal('function')
    })

    it('returns verified when response pubkey matches', async () => {
      axiosGetStub.resolves({ data: { names: { alice: pubkey } } })

      const outcome = await verifyNip05Identifier('alice@example.com', pubkey)

      expect(outcome).to.deep.equal({ status: 'verified' })
    })

    it('returns mismatch when name is not present in response', async () => {
      axiosGetStub.resolves({ data: { names: { bob: pubkey } } })

      const outcome = await verifyNip05Identifier('alice@example.com', pubkey)

      expect(outcome).to.deep.equal({ status: 'mismatch' })
    })

    it('returns mismatch when pubkey does not match', async () => {
      axiosGetStub.resolves({ data: { names: { alice: PUBKEY_B } } })

      const outcome = await verifyNip05Identifier('alice@example.com', pubkey)

      expect(outcome).to.deep.equal({ status: 'mismatch' })
    })

    it('returns invalid when response is not a JSON object', async () => {
      axiosGetStub.resolves({ data: 'not-json' })

      const outcome = await verifyNip05Identifier('alice@example.com', pubkey)

      expect(outcome.status).to.equal('invalid')
    })

    it('returns invalid when names is not an object', async () => {
      axiosGetStub.resolves({ data: { names: 'oops' } })

      const outcome = await verifyNip05Identifier('alice@example.com', pubkey)

      expect(outcome.status).to.equal('invalid')
    })

    it('returns invalid when a pubkey in names is not 64-char hex', async () => {
      axiosGetStub.resolves({ data: { names: { alice: 'not-hex' } } })

      const outcome = await verifyNip05Identifier('alice@example.com', pubkey)

      expect(outcome.status).to.equal('invalid')
    })

    it('returns error on network/timeout failure', async () => {
      axiosGetStub.rejects(new Error('ETIMEDOUT'))

      const outcome = await verifyNip05Identifier('alice@example.com', pubkey)

      expect(outcome.status).to.equal('error')
      if (outcome.status === 'error') {
        expect(outcome.reason).to.equal('ETIMEDOUT')
      }
    })

    describe('beforeRedirect SSRF guard', () => {
      let guard: (options: { href?: string; protocol?: string; hostname?: string }) => void

      before(async () => {
        axiosGetStub.reset()
        axiosGetStub.resolves({ data: { names: { alice: pubkey } } })
        await verifyNip05Identifier('alice@example.com', pubkey)
        guard = axiosGetStub.firstCall.args[1].beforeRedirect
      })

      const allows = (href: string) => {
        expect(() => guard({ href })).not.to.throw()
      }
      const rejects = (href: string) => {
        expect(() => guard({ href })).to.throw(/refused redirect/)
      }

      it('allows https redirects to public hostnames', () => {
        allows('https://other.example.com/.well-known/nostr.json?name=alice')
      })

      it('rejects http redirects', () => {
        rejects('http://example.com/.well-known/nostr.json')
      })

      it('rejects redirects to loopback literal', () => {
        rejects('https://127.0.0.1/')
        rejects('https://127.99.99.99/')
      })

      it('rejects redirects to RFC1918 private ranges', () => {
        rejects('https://10.0.0.1/')
        rejects('https://192.168.1.1/')
        rejects('https://172.16.0.1/')
        rejects('https://172.31.255.254/')
      })

      it('rejects redirects to link-local addresses', () => {
        rejects('https://169.254.169.254/latest/meta-data/')
      })

      it('judges IPv4 literals against the shared blocklist', () => {
        const isRefused = (host: string) => {
          try {
            guard({ href: `https://${host}/.well-known/nostr.json?name=alice` })
            return false
          } catch {
            return true
          }
        }
        const hosts = ['100.100.100.200', '100.64.0.1', '192.0.0.1', '198.18.0.1', '203.0.113.1', '8.8.8.8']

        expect(Object.fromEntries(hosts.map((host) => [host, isRefused(host)]))).to.deep.equal({
          '100.100.100.200': true,
          '100.64.0.1': true,
          '192.0.0.1': true,
          '198.18.0.1': true,
          '203.0.113.1': true,
          '8.8.8.8': false,
        })
      })

      it('names only the scheme and host of a refused target', () => {
        expect(() => guard({ href: 'https://user:secret@100.100.100.200:8443/meta?sig=token' })).to.throw(
          /^refused redirect to unsafe target: https:\/\/100\.100\.100\.200:8443$/,
        )
        expect(() => guard({ href: 'not a url' })).to.throw(/^refused redirect to unsafe target: an invalid URL$/)
      })

      it('rejects redirects to localhost hostname', () => {
        rejects('https://localhost/')
        rejects('https://foo.localhost/')
      })

      it('rejects redirects to IPv6 literals', () => {
        rejects('https://[::1]/')
      })
    })
  })

  describe('verifyNip05Identifier over a real connection', () => {
    const pubkey = PUBKEY_A
    const publicAddresses = [
      { address: '2606:4700::1', family: 6 },
      { address: '8.8.8.8', family: 4 },
    ]
    const refused = (host: string) => ({
      status: 'error',
      reason: `refused NIP-05 target ${host} resolving to a private address`,
    })
    const sandbox = Sinon.createSandbox()
    const proxies: TcpServer[] = []
    let dnsLookup: Sinon.SinonStub
    let server: http.Server
    let redirectTo: string

    const listen = (target: http.Server | TcpServer) =>
      new Promise<void>((resolve, reject) => {
        target.once('error', reject)
        target.listen(0, '127.0.0.1', () => {
          target.off('error', reject)
          resolve()
        })
      })
    const close = (target: http.Server | TcpServer) => new Promise((resolve) => target.close(resolve))

    before(async () => {
      server = http.createServer((req, res) => {
        if (req.headers.host === 'first.example') {
          res.writeHead(302, { location: redirectTo }).end()
          return
        }
        res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ names: { alice: pubkey } }))
      })
      await listen(server)
    })

    after(async () => {
      await close(server)
    })

    beforeEach(() => {
      // Clear proxy settings inherited from the shell, so a broken test can't reach a real proxy.
      sandbox.replace(
        process,
        'env',
        Object.fromEntries(Object.entries(process.env).filter(([name]) => !/proxy$/i.test(name))),
      )
      sandbox.replace(https, 'globalAgent', new https.Agent())
      dnsLookup = sandbox.stub(dns.promises, 'lookup')
      // Fail any lookup that skips the guard instead of querying real DNS.
      const systemLookup: any = dns.lookup
      sandbox
        .stub(dns, 'lookup')
        .callsFake((hostname: string, ...rest: any[]) =>
          isIP(hostname) ? systemLookup(hostname, ...rest) : rest[rest.length - 1](new Error('system DNS used')),
        )
      // Never open a real TLS connection. Run the request's lookup first so guard errors still show;
      // IP literals skip lookup, so refuse them directly.
      const tlsConnect: any = tls.connect
      sandbox.stub(tls, 'connect').callsFake((options: any, ...rest: any[]) => {
        const literal = isIP(options.host ?? '') ? options.host : undefined
        const lookup = (hostname: string, lookupOptions: object, callback: any) => {
          if (literal) {
            callback(new Error(`test refused to dial ${literal}`))
            return
          }
          ;(options.lookup ?? dns.lookup)(hostname, lookupOptions, (error: Error | null) =>
            callback(error ?? new Error(`test refused to dial ${hostname}`)),
          )
        }
        return tlsConnect.call(tls, { ...options, host: literal ? 'literal.invalid' : options.host, lookup }, ...rest)
      })
    })

    afterEach(async () => {
      sandbox.restore()
      await Promise.all(proxies.splice(0).map(close))
    })

    // Serve `hosts` from the local server after running the request's lookup;
    // other hosts go to the real https.request.
    const serveLocally = (hosts: string[]) => {
      const hops: { hostname: string; resolved?: unknown }[] = []
      const request = https.request
      sandbox.stub(https, 'request').callsFake(((options: any, callback: any) => {
        const hop: { hostname: string; resolved?: unknown } = { hostname: options.hostname }
        hops.push(hop)
        if (!hosts.includes(hop.hostname)) {
          return request.call(https, options, callback)
        }
        options.lookup(hop.hostname, { all: true }, (error: Error | null, addresses: unknown) => {
          hop.resolved = error ? error.message : addresses
        })
        const { port } = server.address() as AddressInfo
        const headers = { ...options.headers, host: hop.hostname }
        return http.request(
          { host: '127.0.0.1', port, agent: false, method: options.method, path: options.path, headers },
          callback,
        )
      }) as typeof https.request)
      return hops
    }

    const startProxy = async () => {
      const proxy = { connections: 0, url: '' }
      const proxyServer = createTcpServer((socket) => {
        proxy.connections += 1
        socket.destroy()
      })
      proxies.push(proxyServer)
      await listen(proxyServer)
      proxy.url = `http://127.0.0.1:${(proxyServer.address() as AddressInfo).port}`
      return proxy
    }

    it('refuses a host that resolves to a private address before connecting', async () => {
      for (const addresses of [
        [{ address: '127.0.0.1', family: 4 }],
        [{ address: '::1', family: 6 }],
        [{ address: 'fec0::1', family: 6 }],
        [...publicAddresses, { address: '10.0.0.1', family: 4 }],
      ]) {
        dnsLookup.resolves(addresses)

        const outcome = await verifyNip05Identifier('alice@internal.example', pubkey)

        expect(outcome, JSON.stringify(addresses)).to.deep.equal(refused('internal.example'))
      }
      expect(dnsLookup).to.have.always.been.calledWith('internal.example')
    })

    it('refuses a redirect to a host that resolves to a private address', async () => {
      redirectTo = 'https://internal.example/.well-known/nostr.json?name=alice'
      const hops = serveLocally(['first.example'])
      dnsLookup.resolves(publicAddresses)
      dnsLookup.withArgs('internal.example').resolves([{ address: '192.168.1.10', family: 4 }])

      const outcome = await verifyNip05Identifier('alice@first.example', pubkey)

      expect(outcome).to.deep.equal(refused('internal.example'))
      expect(hops).to.deep.equal([
        { hostname: 'first.example', resolved: publicAddresses },
        { hostname: 'internal.example' },
      ])
    })

    it('still verifies through one redirect, handing every public address to the connection', async () => {
      redirectTo = 'https://second.example/.well-known/nostr.json?name=alice'
      const hops = serveLocally(['first.example', 'second.example'])
      dnsLookup.resolves(publicAddresses)

      const outcome = await verifyNip05Identifier('alice@first.example', pubkey)

      expect(outcome).to.deep.equal({ status: 'verified' })
      expect(hops).to.deep.equal([
        { hostname: 'first.example', resolved: publicAddresses },
        { hostname: 'second.example', resolved: publicAddresses },
      ])
    })

    it('keeps the rest of a refused redirect URL out of the reason', async () => {
      redirectTo = 'https://user:secret@100.100.100.200/latest/meta-data/?sig=token'
      const hops = serveLocally(['first.example', '100.100.100.200'])
      dnsLookup.resolves(publicAddresses)

      const outcome = await verifyNip05Identifier('alice@first.example', pubkey)

      expect(outcome).to.deep.equal({
        status: 'error',
        reason: 'Redirected request failed: refused redirect to unsafe target: https://100.100.100.200',
      })
      expect(hops.map((hop) => hop.hostname)).to.deep.equal(['first.example'])
    })

    it('ignores HTTPS_PROXY, which would resolve the host itself', async () => {
      const proxy = await startProxy()
      Object.assign(process.env, { HTTPS_PROXY: proxy.url, https_proxy: proxy.url })
      dnsLookup.resolves([{ address: '127.0.0.1', family: 4 }])

      const outcome = await verifyNip05Identifier('alice@internal.example', pubkey)

      expect(outcome).to.deep.equal(refused('internal.example'))
      expect(proxy.connections).to.equal(0)
    })

    it("ignores a proxy on Node's global agent (NODE_USE_ENV_PROXY)", async () => {
      const proxy = await startProxy()
      Object.assign(https, { globalAgent: new https.Agent({ proxyEnv: { HTTPS_PROXY: proxy.url } }) })
      dnsLookup.resolves([{ address: '127.0.0.1', family: 4 }])

      const outcome = await verifyNip05Identifier('alice@internal.example', pubkey)

      expect(outcome).to.deep.equal(refused('internal.example'))
      expect(proxy.connections).to.equal(0)
    })
  })
})
