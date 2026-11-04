import { createHash } from "node:crypto";
import type { AssessmentIdentity, CredentialMaterial } from "./types.js";

const forbiddenCustomHeaders = new Set([
  "host",
  "content-length",
  "transfer-encoding",
  "connection",
  "proxy-authorization",
]);
const authHeaders = new Set(["authorization", "cookie", "x-api-key"]);

interface StoredCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  expiresAt: number | null;
}

export interface BrowserCookieValue {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  expires: number;
}

export class IdentityCookieJar {
  readonly #cookies = new Map<string, StoredCookie>();

  setCookie(header: string, requestUrl: string): void {
    const url = new URL(requestUrl);
    const parts = header.split(";").map((part) => part.trim());
    const pair = parts.shift();
    if (!pair) return;
    const separator = pair.indexOf("=");
    if (separator <= 0) return;
    const cookie: StoredCookie = {
      name: pair.slice(0, separator),
      value: pair.slice(separator + 1),
      domain: url.hostname.toLowerCase(),
      path: "/",
      secure: false,
      expiresAt: null,
    };
    for (const attribute of parts) {
      const [rawName, ...rawValue] = attribute.split("=");
      const name = rawName?.toLowerCase();
      const value = rawValue.join("=");
      if (name === "domain" && value) cookie.domain = value.toLowerCase().replace(/^\./, "");
      if (name === "path" && value.startsWith("/")) cookie.path = value;
      if (name === "secure") cookie.secure = true;
      if (name === "max-age") cookie.expiresAt = Date.now() + Number(value) * 1_000;
      if (name === "expires") cookie.expiresAt = Date.parse(value);
    }
    const key = `${cookie.domain}\u0000${cookie.path}\u0000${cookie.name}`;
    if (cookie.value === "" || (cookie.expiresAt !== null && cookie.expiresAt <= Date.now())) {
      this.#cookies.delete(key);
      return;
    }
    this.#cookies.set(key, cookie);
  }

  headerFor(requestUrl: string): string | null {
    const url = new URL(requestUrl);
    const now = Date.now();
    const pairs: string[] = [];
    for (const [key, cookie] of this.#cookies) {
      if (cookie.expiresAt !== null && cookie.expiresAt <= now) {
        this.#cookies.delete(key);
        continue;
      }
      const domainMatch =
        url.hostname === cookie.domain || url.hostname.endsWith(`.${cookie.domain}`);
      if (!domainMatch || !url.pathname.startsWith(cookie.path)) continue;
      if (cookie.secure && url.protocol !== "https:") continue;
      pairs.push(`${cookie.name}=${cookie.value}`);
    }
    return pairs.length > 0 ? pairs.join("; ") : null;
  }

  clear(): void {
    this.#cookies.clear();
  }

  fingerprints(): readonly string[] {
    return [...this.#cookies.values()].map(({ name, value }) =>
      createHash("sha256").update(`${name}=${value}`).digest("hex"),
    );
  }

  browserCookies(requestUrl: string): readonly BrowserCookieValue[] {
    const url = new URL(requestUrl);
    const now = Date.now();
    return [...this.#cookies.values()]
      .filter((cookie) => {
        const domainMatch =
          url.hostname === cookie.domain || url.hostname.endsWith(`.${cookie.domain}`);
        return (
          domainMatch &&
          url.pathname.startsWith(cookie.path) &&
          (!cookie.secure || url.protocol === "https:") &&
          (cookie.expiresAt === null || cookie.expiresAt > now)
        );
      })
      .map((cookie) => ({
        name: cookie.name,
        value: cookie.value,
        domain: cookie.domain,
        path: cookie.path,
        secure: cookie.secure,
        expires: cookie.expiresAt === null ? -1 : Math.floor(cookie.expiresAt / 1_000),
      }));
  }
}

export class IdentityRequestContext {
  readonly cookieJar = new IdentityCookieJar();
  readonly #headers = new Map<string, string>();
  readonly #csrfState = new Map<string, string>();

  constructor(readonly identity: AssessmentIdentity) {}

  applyCredential(material: CredentialMaterial): void {
    if (material.type !== this.identity.authenticationType) {
      throw new Error(`Credential type does not match identity ${this.identity.id}.`);
    }
    if (material.type === "ANONYMOUS") return this.assertAnonymous();
    if (material.type === "BEARER_TOKEN")
      this.#headers.set("authorization", `Bearer ${material.token}`);
    if (material.type === "API_KEY") this.setHeader(material.headerName, material.value);
    if (material.type === "CUSTOM_HEADERS") {
      for (const [name, value] of Object.entries(material.headers)) this.setHeader(name, value);
    }
    if (material.type === "SESSION_COOKIE") {
      const base = `${material.domain ?? "localhost"}${material.path ?? "/"}`;
      this.cookieJar.setCookie(
        `${material.name}=${material.value}; Path=${material.path ?? "/"}${material.domain ? `; Domain=${material.domain}` : ""}`,
        `https://${base.replace(/^https?:\/\//, "")}`,
      );
    }
  }

  setHeader(name: string, value: string): void {
    const normalized = name.toLowerCase().trim();
    if (!normalized || forbiddenCustomHeaders.has(normalized) || /[\r\n]/u.test(name + value)) {
      throw new Error(`Header ${name} is not permitted in an identity context.`);
    }
    this.#headers.set(normalized, value);
  }

  setCsrf(key: string, value: string): void {
    this.#csrfState.set(key, value);
  }

  getCsrf(key: string): string | undefined {
    return this.#csrfState.get(key);
  }

  requestHeaders(
    url: string,
    additional: Readonly<Record<string, string>> = {},
  ): Record<string, string> {
    const result = Object.fromEntries(this.#headers);
    const cookie = this.cookieJar.headerFor(url);
    if (cookie) result["cookie"] = cookie;
    for (const [name, value] of Object.entries(additional)) {
      const normalized = name.toLowerCase();
      if (authHeaders.has(normalized))
        throw new Error("Test cases cannot override identity authentication headers.");
      if (forbiddenCustomHeaders.has(normalized) || /[\r\n]/u.test(name + value)) {
        throw new Error(`Header ${name} is not permitted.`);
      }
      result[normalized] = value;
    }
    if (this.identity.authenticationType === "ANONYMOUS") this.assertAnonymousHeaders(result);
    return result;
  }

  ingestResponse(
    headers: Readonly<Record<string, string | string[] | undefined>>,
    url: string,
  ): void {
    const setCookie = headers["set-cookie"];
    for (const value of Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : []) {
      this.cookieJar.setCookie(value, url);
    }
  }

  assertAnonymous(): void {
    this.assertAnonymousHeaders(Object.fromEntries(this.#headers));
    if (this.cookieJar.fingerprints().length > 0 || this.#csrfState.size > 0) {
      throw new Error("Anonymous identity contains residual session state.");
    }
  }

  private assertAnonymousHeaders(headers: Readonly<Record<string, string>>): void {
    if (Object.keys(headers).some((name) => authHeaders.has(name.toLowerCase()))) {
      throw new Error("Anonymous identity contains an authentication header.");
    }
  }

  sessionFingerprint(): string | null {
    const material = [
      ...[...this.#headers.entries()]
        .filter(([name]) => authHeaders.has(name))
        .map(([name, value]) => `${name}:${value}`),
      ...this.cookieJar.fingerprints(),
    ].sort();
    return material.length > 0
      ? createHash("sha256").update(material.join("\n")).digest("hex")
      : null;
  }

  browserBootstrap(origin: string): Readonly<Record<string, unknown>> {
    const headers = Object.fromEntries(
      [...this.#headers.entries()].filter(([name]) => name !== "cookie"),
    );
    if (this.identity.authenticationType === "ANONYMOUS") this.assertAnonymous();
    return {
      identityId: this.identity.id,
      sessionFingerprint: this.sessionFingerprint(),
      extraHTTPHeaders: headers,
      cookies: this.cookieJar.browserCookies(origin),
    };
  }

  dispose(): void {
    this.cookieJar.clear();
    this.#headers.clear();
    this.#csrfState.clear();
  }
}
