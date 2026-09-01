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

function normalizedV6(address: string): string {
  return address.toLowerCase().split("%")[0] ?? address.toLowerCase();
}

function mappedV4(address: string): string | undefined {
  const value = normalizedV6(address);
  const match = /^(?:::ffff:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(value);
  return match?.[1];
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
    const mapped = mappedV4(address);
    if (mapped) return classifyAddress(mapped);
    const value = normalizedV6(address);
    if (value === "::" || value === "0:0:0:0:0:0:0:0") return "UNSPECIFIED";
    if (value === "::1" || value === "0:0:0:0:0:0:0:1") return "LOOPBACK";
    if (
      value.startsWith("fe8") ||
      value.startsWith("fe9") ||
      value.startsWith("fea") ||
      value.startsWith("feb")
    )
      return "LINK_LOCAL";
    if (value.startsWith("fc") || value.startsWith("fd")) return "PRIVATE";
    if (value.startsWith("ff")) return "MULTICAST";
    if (value.startsWith("2001:db8")) return "DOCUMENTATION";
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
