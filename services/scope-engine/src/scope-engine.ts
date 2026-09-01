import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";
import { isBlockedAddress } from "./ip-policy.js";
import { ScopeViolationError } from "./errors.js";

export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

export interface HostResolver {
  resolve(hostname: string): Promise<ResolvedAddress[]>;
}

export interface ScopePolicy {
  targetOrigin: string;
  allowedDomains?: string[];
  includeSubdomains: boolean;
  allowPrivateNetwork: boolean;
  allowedPorts?: number[];
  excludedPathPrefixes?: string[];
}

export interface PersistedTargetScope {
  origin: string;
  includeSubdomains: boolean;
  allowPrivateNetwork: boolean;
  scopeRules: Array<{ type: string; value: string; enabled: boolean }>;
}

export interface ScopeDecision {
  url: URL;
  normalizedUrl: string;
  addresses: ResolvedAddress[];
  selectedAddress: ResolvedAddress;
}

const forbiddenHostnames = new Set([
  "localhost",
  "localhost.localdomain",
  "metadata.google.internal",
  "metadata.google.internal.",
  "instance-data.ec2.internal",
]);

export class SystemHostResolver implements HostResolver {
  async resolve(hostname: string): Promise<ResolvedAddress[]> {
    const records = await lookup(hostname, { all: true, verbatim: true });
    return records
      .filter(
        (record): record is { address: string; family: 4 | 6 } =>
          record.family === 4 || record.family === 6,
      )
      .map((record) => ({ address: record.address, family: record.family }));
  }
}

export class DnsPinStore {
  private readonly pins = new Map<string, ReadonlySet<string>>();

  assertStable(hostname: string, addresses: ResolvedAddress[]): void {
    const current = new Set(addresses.map(({ address }) => address));
    const pinned = this.pins.get(hostname);
    if (!pinned) {
      this.pins.set(hostname, current);
      return;
    }
    if (current.size === 0 || [...current].some((address) => !pinned.has(address))) {
      throw new ScopeViolationError(
        "DNS_REBINDING_DETECTED",
        `DNS answers for ${hostname} changed outside the pinned address set.`,
      );
    }
  }
}

function normalizeHostname(hostname: string): string {
  const withoutBrackets =
    hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  const withoutTrailingDot = withoutBrackets.toLowerCase().replace(/\.$/, "");
  if (isIP(withoutTrailingDot) !== 0) return withoutTrailingDot;
  const ascii = domainToASCII(withoutTrailingDot);
  if (!ascii || ascii.length > 253) {
    throw new ScopeViolationError("INVALID_URL", "Hostname is invalid.");
  }
  return ascii;
}

function effectivePort(url: URL): number {
  if (url.port) return Number(url.port);
  return url.protocol === "https:" ? 443 : 80;
}

export function scopePolicyFromTarget(target: PersistedTargetScope): ScopePolicy {
  const origin = normalizeAssessmentUrl(target.origin);
  const allowedDomains = [
    ...new Set(
      target.scopeRules
        .filter(({ enabled, type }) => enabled && type === "HOST")
        .map(({ value }) => normalizeHostname(value)),
    ),
  ];
  const allowedPorts = [
    ...new Set(
      target.scopeRules
        .filter(({ enabled, type }) => enabled && type === "PORT")
        .map(({ value }) => Number(value))
        .filter((value) => Number.isInteger(value) && value >= 1 && value <= 65_535),
    ),
  ];
  const excludedPathPrefixes = [
    ...new Set(
      target.scopeRules
        .filter(({ enabled, type }) => enabled && type === "PATH_EXCLUDE")
        .map(({ value }) => value),
    ),
  ];
  if (allowedDomains.length === 0) {
    throw new ScopeViolationError(
      "SCOPE_NOT_CONFIGURED",
      "At least one allowed domain is required.",
    );
  }
  if (allowedPorts.length === 0) {
    throw new ScopeViolationError("SCOPE_NOT_CONFIGURED", "At least one allowed port is required.");
  }
  const originHostname = normalizeHostname(origin.hostname);
  if (!allowedDomains.includes(originHostname)) {
    throw new ScopeViolationError(
      "SCOPE_NOT_CONFIGURED",
      "The target origin hostname must be explicitly present in allowed domains.",
    );
  }
  if (!allowedPorts.includes(effectivePort(origin))) {
    throw new ScopeViolationError(
      "SCOPE_NOT_CONFIGURED",
      "The target origin port must be explicitly present in allowed ports.",
    );
  }
  return {
    targetOrigin: origin.toString(),
    allowedDomains,
    includeSubdomains: target.includeSubdomains,
    allowPrivateNetwork: target.allowPrivateNetwork,
    allowedPorts,
    excludedPathPrefixes,
  };
}

export function normalizeAssessmentUrl(input: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(input);
  } catch {
    throw new ScopeViolationError("INVALID_URL", "The supplied URL is invalid.", input);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new ScopeViolationError(
      "UNEXPECTED_SCHEME",
      "Only HTTP and HTTPS URLs are permitted.",
      input,
    );
  }
  if (parsed.username || parsed.password) {
    throw new ScopeViolationError(
      "CREDENTIALS_IN_URL",
      "Credentials in URLs are prohibited.",
      input,
    );
  }
  const normalizedHostname = normalizeHostname(parsed.hostname);
  parsed.hostname = isIP(normalizedHostname) === 6 ? `[${normalizedHostname}]` : normalizedHostname;
  parsed.hash = "";
  if (
    (parsed.protocol === "http:" && parsed.port === "80") ||
    (parsed.protocol === "https:" && parsed.port === "443")
  )
    parsed.port = "";
  return parsed;
}

export class ScopeEngine {
  constructor(
    private readonly resolver: HostResolver = new SystemHostResolver(),
    private readonly pins: DnsPinStore = new DnsPinStore(),
  ) {}

  async assertAllowed(input: string | URL, policy: ScopePolicy): Promise<ScopeDecision> {
    const url = normalizeAssessmentUrl(input instanceof URL ? input.toString() : input);
    const target = normalizeAssessmentUrl(policy.targetOrigin);
    const hostname = normalizeHostname(url.hostname);
    const targetHostname = normalizeHostname(target.hostname);
    const allowedDomains = (policy.allowedDomains ?? [targetHostname]).map(normalizeHostname);

    if (forbiddenHostnames.has(hostname) && !policy.allowPrivateNetwork) {
      throw new ScopeViolationError(
        "ADDRESS_BLOCKED",
        `Hostname ${hostname} is blocked.`,
        url.toString(),
      );
    }

    const exactHost = allowedDomains.includes(hostname);
    const authorizedSubdomain =
      policy.includeSubdomains &&
      allowedDomains.some((allowedDomain) => hostname.endsWith(`.${allowedDomain}`));
    if (!exactHost && !authorizedSubdomain) {
      throw new ScopeViolationError(
        "HOST_NOT_AUTHORIZED",
        `Host ${hostname} is outside authorized scope.`,
        url.toString(),
      );
    }

    const port = effectivePort(url);
    const targetPort = effectivePort(target);
    const allowedPorts = new Set(policy.allowedPorts ?? [targetPort]);
    if (!allowedPorts.has(port)) {
      throw new ScopeViolationError(
        "PORT_NOT_AUTHORIZED",
        `Port ${port} is outside authorized scope.`,
        url.toString(),
      );
    }

    if ((policy.excludedPathPrefixes ?? []).some((prefix) => url.pathname.startsWith(prefix))) {
      throw new ScopeViolationError(
        "PATH_EXCLUDED",
        `Path ${url.pathname} is excluded from scope.`,
        url.toString(),
      );
    }

    let addresses: ResolvedAddress[];
    try {
      addresses = await this.resolver.resolve(hostname);
    } catch (error: unknown) {
      throw new ScopeViolationError(
        "RESOLUTION_FAILED",
        `DNS resolution failed for ${hostname}: ${error instanceof Error ? error.message : "unknown error"}`,
        url.toString(),
      );
    }
    if (addresses.length === 0) {
      throw new ScopeViolationError(
        "RESOLUTION_FAILED",
        `DNS resolution returned no addresses for ${hostname}.`,
        url.toString(),
      );
    }
    for (const { address } of addresses) {
      if (isBlockedAddress(address, policy.allowPrivateNetwork)) {
        throw new ScopeViolationError(
          "ADDRESS_BLOCKED",
          `Resolved address ${address} is prohibited by scope policy.`,
          url.toString(),
        );
      }
    }
    this.pins.assertStable(hostname, addresses);

    return {
      url,
      normalizedUrl: url.toString(),
      addresses,
      selectedAddress: addresses[0] as ResolvedAddress,
    };
  }
}
