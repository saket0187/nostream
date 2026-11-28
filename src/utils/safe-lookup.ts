import { lookup as dnsLookup } from 'node:dns/promises'
import { BlockList, isIP } from 'node:net'

const blockedAddresses = new BlockList()
blockedAddresses.addSubnet('0.0.0.0', 8, 'ipv4')
blockedAddresses.addSubnet('10.0.0.0', 8, 'ipv4')
blockedAddresses.addSubnet('100.64.0.0', 10, 'ipv4')
blockedAddresses.addSubnet('127.0.0.0', 8, 'ipv4')
blockedAddresses.addSubnet('169.254.0.0', 16, 'ipv4')
blockedAddresses.addSubnet('172.16.0.0', 12, 'ipv4')
blockedAddresses.addSubnet('192.0.0.0', 24, 'ipv4')
blockedAddresses.addSubnet('192.0.2.0', 24, 'ipv4')
blockedAddresses.addSubnet('192.168.0.0', 16, 'ipv4')
blockedAddresses.addSubnet('198.18.0.0', 15, 'ipv4')
blockedAddresses.addSubnet('198.51.100.0', 24, 'ipv4')
blockedAddresses.addSubnet('203.0.113.0', 24, 'ipv4')
blockedAddresses.addSubnet('224.0.0.0', 4, 'ipv4')
blockedAddresses.addSubnet('240.0.0.0', 4, 'ipv4')
blockedAddresses.addSubnet('::', 128, 'ipv6')
blockedAddresses.addSubnet('::1', 128, 'ipv6')
blockedAddresses.addSubnet('2001:db8::', 32, 'ipv6')
blockedAddresses.addSubnet('fc00::', 7, 'ipv6')
blockedAddresses.addSubnet('fe80::', 10, 'ipv6')
blockedAddresses.addSubnet('fec0::', 10, 'ipv6')
blockedAddresses.addSubnet('ff00::', 8, 'ipv6')

const normalizeResolvedAddress = (address: string): string => {
  const lower = address.toLowerCase()
  const mapped = lower.startsWith('::ffff:') ? lower.slice('::ffff:'.length) : lower

  return isIP(mapped) === 4 ? mapped : lower
}

export const isBlockedAddress = (address: string): boolean => {
  const normalized = normalizeResolvedAddress(address)
  const family = isIP(normalized)

  if (family === 4) {
    return blockedAddresses.check(normalized, 'ipv4')
  }

  if (family === 6) {
    return blockedAddresses.check(normalized, 'ipv6')
  }

  return true
}

/**
 * Build a request `lookup` that resolves the host and refuses private/loopback/link-local
 * results before the socket connects. String-only URL checks miss hostnames whose A/AAAA
 * records point inward, including DNS rebinding after the literal check. Node does not call
 * `lookup` for an IP literal host, so callers must check literals with isBlockedAddress.
 */
export const createSafeLookup =
  (target: string) =>
  async (hostname: string, options: object): Promise<[{ address: string; family: number }[]]> => {
    const result = await dnsLookup(hostname, { ...(options as any), all: true })
    const addresses = Array.isArray(result) ? result : [result]

    if (addresses.some((entry) => isBlockedAddress(entry.address))) {
      throw new Error(`refused ${target} target ${hostname} resolving to a private address`)
    }

    // axios reads an async lookup's result as [address(es), family]; a flat array would keep only the first address.
    return [addresses]
  }
