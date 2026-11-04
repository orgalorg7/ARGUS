import { isIP } from "node:net";

function ipv4Number(address: string): number | undefined {
  const parts = address.split(".");
  if (parts.length !== 4) return undefined;
  const octets = parts.map((part) => Number(part));
  if (octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return undefined;
  return (
    (((octets[0] ?? 0) << 24) |
      ((octets[1] ?? 0) << 16) |
      ((octets[2] ?? 0) << 8) |
      (octets[3] ?? 0)) >>>
    0
  );
}

function inV4Cidr(address: string, network: string, prefix: number): boolean {
  const ip = ipv4Number(address);
  const base = ipv4Number(network);
  if (ip === undefined || base === undefined) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ip & mask) === (base & mask);
}

function v6Number(address: string): bigint {
  // WHATWG canonicalization collapses expanded forms and converts embedded IPv4 to hex.
  const normalized = new URL(`http://[${address}]/`).hostname.slice(1, -1);
  const [left = "", right] = normalized.split("::");
  const head = left ? left.split(":") : [];
  const tail = right ? right.split(":") : [];
  const parts =
    right === undefined
      ? head
      : [...head, ...Array<string>(8 - head.length - tail.length).fill("0"), ...tail];
  return parts.reduce((value, part) => (value << 16n) | BigInt(`0x${part}`), 0n);
}

export type AddressClassification =
  | "PUBLIC"
  | "LOOPBACK"
  | "PRIVATE"
  | "LINK_LOCAL"
  | "MULTICAST"
  | "DOCUMENTATION"
  | "UNSPECIFIED"
  | "RESERVED";

export function classifyAddress(address: string): AddressClassification {
  const family = isIP(address);
  if (family === 0) return "RESERVED";
  if (family === 6) {
    if (address.includes("%")) return "RESERVED";
    const value = v6Number(address);
    const inRange = (network: string, prefix: number) =>
      value >> BigInt(128 - prefix) === v6Number(network) >> BigInt(128 - prefix);
    if (inRange("::ffff:0:0", 96)) {
      const v4 = Number(value & 0xffffffffn);
      return classifyAddress([v4 >>> 24, (v4 >>> 16) & 255, (v4 >>> 8) & 255, v4 & 255].join("."));
    }
    if (value === 0n) return "UNSPECIFIED";
    if (value === 1n) return "LOOPBACK";
    if (inRange("fe80::", 10)) return "LINK_LOCAL";
    if (inRange("fc00::", 7)) return "PRIVATE";
    if (inRange("ff00::", 8)) return "MULTICAST";
    if (inRange("2001:db8::", 32) || inRange("3fff::", 20)) return "DOCUMENTATION";
    // Translation/tunnel and reserved ranges are not general-purpose assessment destinations.
    if (!inRange("2000::", 3) || inRange("2001::", 23) || inRange("2002::", 16)) return "RESERVED";
    return "PUBLIC";
  }
  if (inV4Cidr(address, "127.0.0.0", 8)) return "LOOPBACK";
  if (
    inV4Cidr(address, "10.0.0.0", 8) ||
    inV4Cidr(address, "172.16.0.0", 12) ||
    inV4Cidr(address, "192.168.0.0", 16)
  )
    return "PRIVATE";
  if (inV4Cidr(address, "169.254.0.0", 16)) return "LINK_LOCAL";
  if (inV4Cidr(address, "224.0.0.0", 4)) return "MULTICAST";
  if (inV4Cidr(address, "0.0.0.0", 8)) return "UNSPECIFIED";
  if (
    inV4Cidr(address, "192.0.2.0", 24) ||
    inV4Cidr(address, "198.51.100.0", 24) ||
    inV4Cidr(address, "203.0.113.0", 24)
  )
    return "DOCUMENTATION";
  if (
    inV4Cidr(address, "100.64.0.0", 10) ||
    inV4Cidr(address, "198.18.0.0", 15) ||
    inV4Cidr(address, "240.0.0.0", 4)
  )
    return "RESERVED";
  return "PUBLIC";
}

export function isBlockedAddress(address: string, allowPrivateNetwork: boolean): boolean {
  const classification = classifyAddress(address);
  if (classification === "PUBLIC") return false;
  if (allowPrivateNetwork && (classification === "PRIVATE" || classification === "LOOPBACK"))
    return false;
  return true;
}
