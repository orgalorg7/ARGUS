import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import type { IncomingHttpHeaders } from "node:http";
import { ScopeViolationError } from "./errors.js";
import type { ScopePolicy } from "./scope-engine.js";
import type { ScopeEngine } from "./scope-engine.js";

export interface ScopedRequestOptions {
  method?: "GET" | "HEAD" | "OPTIONS";
  headers?: Readonly<Record<string, string>>;
  timeoutMs?: number;
  maxResponseBytes?: number;
  followRedirects?: boolean;
  maxRedirects?: number;
  signal?: AbortSignal;
}

export interface ScopedResponse {
  requestedUrl: string;
  finalUrl: string;
  statusCode: number;
  headers: IncomingHttpHeaders;
  body: Buffer;
  redirects: string[];
  tls?: ScopedTlsMetadata;
}

export interface ScopedTlsMetadata {
  protocol: string | null;
  cipher: string | null;
  authorized: boolean;
  authorizationError: string | null;
  peerCertificate: {
    subject: string;
    issuer: string;
    validFrom: string;
    validTo: string;
    subjectAltName: string;
    fingerprint256: string;
  };
}

const safeMethods = new Set(["GET", "HEAD", "OPTIONS"]);
const redirectCodes = new Set([301, 302, 303, 307, 308]);
const sensitiveHeaders = new Set(["authorization", "cookie", "proxy-authorization", "x-api-key"]);

export class ScopedHttpClient {
  constructor(
    private readonly scopeEngine: ScopeEngine,
    private readonly policy: ScopePolicy,
  ) {}

  async request(url: string, options: ScopedRequestOptions = {}): Promise<ScopedResponse> {
    const method = options.method ?? "GET";
    if (!safeMethods.has(method)) {
      throw new ScopeViolationError(
        "UNSAFE_METHOD",
        `HTTP method ${method} is not enabled for scoped assessment requests.`,
        url,
      );
    }
    return this.execute(url, options, [], 0);
  }

  private async execute(
    requestedUrl: string,
    options: ScopedRequestOptions,
    redirects: string[],
    redirectCount: number,
  ): Promise<ScopedResponse> {
    const decision = await this.scopeEngine.assertAllowed(requestedUrl, this.policy);
    const method = options.method ?? "GET";
    const timeoutMs = options.timeoutMs ?? 15_000;
    const maxResponseBytes = options.maxResponseBytes ?? 5 * 1024 * 1024;
    const transport = decision.url.protocol === "https:" ? https : http;
    const selected = decision.selectedAddress;

    const result = await new Promise<
      Omit<ScopedResponse, "requestedUrl" | "finalUrl" | "redirects">
    >((resolve, reject) => {
      const request = transport.request(
        decision.url,
        {
          method,
          headers: {
            "user-agent": "AuthorizedSecurityAssessment/0.1",
            accept: "*/*",
            ...options.headers,
            host: decision.url.host,
          },
          servername: decision.url.hostname,
          lookup: (_hostname, lookupOptions, callback) => {
            if (lookupOptions.all) {
              callback(null, [{ address: selected.address, family: selected.family }]);
              return;
            }
            callback(null, selected.address, selected.family);
          },
          signal: options.signal,
        },
        (response) => {
          const chunks: Buffer[] = [];
          let size = 0;
          response.on("data", (chunk: Buffer | string) => {
            const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            size += buffer.length;
            if (size > maxResponseBytes) {
              request.destroy(new Error(`Response exceeded ${maxResponseBytes} bytes.`));
              return;
            }
            chunks.push(buffer);
          });
          response.on("end", () => {
            const socket = response.socket;
            const certificate =
              socket instanceof tls.TLSSocket ? socket.getPeerCertificate() : null;
            const tlsMetadata =
              socket instanceof tls.TLSSocket
                ? {
                    protocol: socket.getProtocol(),
                    cipher: socket.getCipher()?.name ?? null,
                    authorized: socket.authorized,
                    authorizationError: socket.authorizationError?.message ?? null,
                    peerCertificate: {
                      subject: certificate?.subject?.CN ?? "",
                      issuer: certificate?.issuer?.CN ?? "",
                      validFrom: certificate?.valid_from ?? "",
                      validTo: certificate?.valid_to ?? "",
                      subjectAltName: certificate?.subjectaltname ?? "",
                      fingerprint256: certificate?.fingerprint256 ?? "",
                    },
                  }
                : undefined;
            resolve({
              statusCode: response.statusCode ?? 0,
              headers: response.headers,
              body: Buffer.concat(chunks),
              ...(tlsMetadata ? { tls: tlsMetadata } : {}),
            });
          });
        },
      );
      request.setTimeout(timeoutMs, () =>
        request.destroy(new Error(`Request timed out after ${timeoutMs} ms.`)),
      );
      request.on("error", reject);
      request.end();
    });

    const location = result.headers.location;
    if (options.followRedirects !== false && redirectCodes.has(result.statusCode) && location) {
      const maxRedirects = options.maxRedirects ?? 5;
      if (redirectCount >= maxRedirects) {
        throw new ScopeViolationError(
          "REDIRECT_LIMIT_EXCEEDED",
          `Redirect limit of ${maxRedirects} exceeded.`,
          decision.normalizedUrl,
        );
      }
      const redirectUrl = new URL(location, decision.url).toString();
      await this.scopeEngine.assertAllowed(redirectUrl, this.policy);
      const sanitizedHeaders = Object.fromEntries(
        Object.entries(options.headers ?? {}).filter(
          ([name]) => !sensitiveHeaders.has(name.toLowerCase()),
        ),
      );
      return this.execute(
        redirectUrl,
        { ...options, headers: sanitizedHeaders },
        [...redirects, redirectUrl],
        redirectCount + 1,
      );
    }

    return {
      requestedUrl,
      finalUrl: decision.normalizedUrl,
      ...result,
      redirects,
    };
  }
}
