import type { ScannerObservationInput } from "@aasp/schemas";
import {
  headerValues,
  observation,
  type HttpExchange,
  type PassiveScannerAdapter,
} from "@aasp/scanner-integrations";
import type { ScopedHttpClient, ScopedResponse } from "@aasp/scope-engine";

const csrfNamePattern = /(?:^|[_-])(?:csrf|xsrf|anti[_-]?forgery|request[_-]?token)(?:$|[_-])/i;
const unsafeFormMethods = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const redirectParameterPattern =
  /^(?:url|uri|next|redirect|redirect_url|redirect_uri|return|return_to|returnurl|continue|callback|destination|dest)$/i;
const harmlessRedirectDestination = "https://aasp-redirect-check.invalid/authorized-assessment";
const inertReflectionMarker = "aasp_reflection_probe_7f31c9";
const sensitiveParameterPattern =
  /(?:^|[_-])(?:access[_-]?token|api[_-]?key|auth|authorization|code|credential|jwt|password|secret|session|signature|sig|token)(?:$|[_-])/i;

interface HtmlForm {
  action: string;
  method: string;
  inputNames: string[];
  hasFileInput: boolean;
}

interface SecretPattern {
  type: string;
  pattern: RegExp;
}

const secretPatterns: readonly SecretPattern[] = [
  { type: "AWS_ACCESS_KEY_ID", pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { type: "GITHUB_TOKEN", pattern: /\bgh[opsu]_[A-Za-z0-9]{30,255}\b/g },
  { type: "GOOGLE_API_KEY", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { type: "PRIVATE_KEY_BLOCK", pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  {
    type: "JWT_LITERAL",
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  },
];

function attributeValue(attributes: string, name: string): string | null {
  const match = new RegExp(`(?:^|\\s)${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i").exec(
    attributes,
  );
  return match?.[1] ?? match?.[2] ?? match?.[3] ?? null;
}

function parseForms(body: string): HtmlForm[] {
  const forms: HtmlForm[] = [];
  for (const match of body.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form\s*>/gi)) {
    const attributes = match[1] ?? "";
    const content = match[2] ?? "";
    const inputNames = [...content.matchAll(/<(?:input|button)\b([^>]*)>/gi)]
      .map((input) => attributeValue(input[1] ?? "", "name"))
      .filter((name): name is string => Boolean(name));
    const hasFileInput = [...content.matchAll(/<input\b([^>]*)>/gi)].some(
      (input) => attributeValue(input[1] ?? "", "type")?.toLowerCase() === "file",
    );
    forms.push({
      action: attributeValue(attributes, "action") ?? "",
      method: (attributeValue(attributes, "method") ?? "GET").toUpperCase(),
      inputNames,
      hasFileInput,
    });
  }
  return forms;
}

function isHtml(exchange: HttpExchange): boolean {
  return headerValues(exchange.headers, "content-type")
    .join(";")
    .toLowerCase()
    .includes("text/html");
}

function isJavaScript(exchange: HttpExchange): boolean {
  const contentType = headerValues(exchange.headers, "content-type").join(";").toLowerCase();
  const path = new URL(exchange.finalUrl).pathname;
  return /(?:javascript|ecmascript)/i.test(contentType) || /\.(?:m?js)$/i.test(path);
}

function uniqueMatches(body: string, pattern: RegExp): string[] {
  return [...new Set([...body.matchAll(pattern)].map((match) => match[0]))];
}

function safeUrl(value: string, visibleParameter?: string): string {
  try {
    const parsed = new URL(value);
    parsed.username = "";
    parsed.password = "";
    for (const name of [...new Set(parsed.searchParams.keys())]) {
      if (name !== visibleParameter) parsed.searchParams.set(name, "[REDACTED]");
    }
    return parsed.toString();
  } catch {
    return "[INVALID_URL_REDACTED]";
  }
}

export class ApplicationSurfaceScanner implements PassiveScannerAdapter {
  readonly name = "aasp-application";
  readonly version = "0.1.0";

  analyze(exchanges: readonly HttpExchange[]): ScannerObservationInput[] {
    const results: ScannerObservationInput[] = [];
    for (const exchange of exchanges) {
      if (isHtml(exchange)) this.analyzeHtml(exchange, results);
      if (isJavaScript(exchange)) this.analyzeJavaScript(exchange, results);
    }
    return results;
  }

  private analyzeHtml(exchange: HttpExchange, results: ScannerObservationInput[]): void {
    const forms = parseForms(exchange.body);
    for (const form of forms) {
      const action = form.action || new URL(exchange.finalUrl).pathname;
      results.push(
        observation(
          this,
          exchange,
          "FORM_INPUT_SURFACE_OBSERVED",
          {
            action,
            method: form.method,
            inputNames: form.inputNames,
            hasFileInput: form.hasFileInput,
          },
          {
            rawSeverity: "INFO",
            method: form.method,
            excerpt: `Form observed: method=${form.method}; action=${action}; fields=${form.inputNames.join(",") || "none"}.`,
          },
        ),
      );
      if (form.hasFileInput) {
        results.push(
          observation(
            this,
            exchange,
            "FILE_UPLOAD_SURFACE_OBSERVED",
            { action, method: form.method, inputNames: form.inputNames },
            {
              rawSeverity: "INFO",
              method: form.method,
              excerpt: `File upload surface observed at form action ${action}. No file was uploaded.`,
            },
          ),
        );
      }
      if (
        unsafeFormMethods.has(form.method) &&
        !form.inputNames.some((name) => csrfNamePattern.test(name))
      ) {
        results.push(
          observation(
            this,
            exchange,
            "FORM_CSRF_PROTECTION_NOT_OBSERVED",
            { action, formMethod: form.method, inspectedFieldNames: form.inputNames },
            {
              rawSeverity: "LOW",
              method: form.method,
              excerpt: `State-changing form has no recognizable anti-CSRF field: method=${form.method}; action=${action}. Header/origin controls were not evaluated by this passive check.`,
            },
          ),
        );
      }
    }

    if (new URL(exchange.finalUrl).protocol === "https:") {
      const mixedReferences = uniqueMatches(
        exchange.body,
        /(?:src|href)\s*=\s*["']http:\/\/[^"']+["']/gi,
      );
      if (mixedReferences.length > 0) {
        results.push(
          observation(
            this,
            exchange,
            "MIXED_CONTENT_REFERENCE_OBSERVED",
            { referenceCount: mixedReferences.length },
            {
              rawSeverity: "LOW",
              excerpt: `HTTPS document contains ${mixedReferences.length} explicit HTTP resource reference(s).`,
            },
          ),
        );
      }
    }
  }

  private analyzeJavaScript(exchange: HttpExchange, results: ScannerObservationInput[]): void {
    const sinkPatterns: Array<[string, RegExp]> = [
      ["innerHTML", /\.innerHTML\s*=/g],
      ["outerHTML", /\.outerHTML\s*=/g],
      ["insertAdjacentHTML", /\.insertAdjacentHTML\s*\(/g],
      ["document.write", /\bdocument\.write(?:ln)?\s*\(/g],
      ["eval", /(?:^|[^.\w])eval\s*\(/g],
      ["Function constructor", /\bnew\s+Function\s*\(/g],
    ];
    for (const [sink, pattern] of sinkPatterns) {
      const count = [...exchange.body.matchAll(pattern)].length;
      if (count === 0) continue;
      results.push(
        observation(
          this,
          exchange,
          "UNSAFE_DOM_SINK_INDICATOR",
          { sink, occurrenceCount: count },
          {
            rawSeverity: "LOW",
            excerpt: `Client bundle contains ${count} occurrence(s) of the potentially unsafe ${sink} sink. Data flow was not proven.`,
          },
        ),
      );
    }

    for (const secret of secretPatterns) {
      const count = [...exchange.body.matchAll(secret.pattern)].length;
      if (count === 0) continue;
      results.push(
        observation(
          this,
          exchange,
          "CLIENT_SECRET_PATTERN_OBSERVED",
          { secretType: secret.type, occurrenceCount: count, valueRetained: false },
          {
            rawSeverity: "MEDIUM",
            excerpt: `[REDACTED ${secret.type}] pattern observed ${count} time(s) in client-side code. The matched value was not retained.`,
          },
        ),
      );
    }

    const webSockets = uniqueMatches(exchange.body, /\bwss?:\/\/[^\s"'`<>]+/g);
    for (const observedEndpoint of webSockets.slice(0, 20)) {
      const endpoint = safeUrl(observedEndpoint);
      results.push(
        observation(
          this,
          exchange,
          "WEBSOCKET_ENDPOINT_OBSERVED",
          { endpoint },
          { rawSeverity: "INFO", excerpt: `WebSocket endpoint reference observed: ${endpoint}` },
        ),
      );
    }

    const developmentReferences = uniqueMatches(
      exchange.body,
      /https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|[A-Za-z0-9.-]+\.(?:local|internal))(?::\d+)?[^\s"'`]*/gi,
    );
    if (developmentReferences.length > 0) {
      results.push(
        observation(
          this,
          exchange,
          "CLIENT_DEVELOPMENT_ENDPOINT_DISCLOSURE",
          { referenceCount: developmentReferences.length },
          {
            rawSeverity: "INFO",
            excerpt: `Client bundle contains ${developmentReferences.length} local or internal endpoint reference(s); values omitted from evidence.`,
          },
        ),
      );
    }
  }
}

function responseHeader(response: ScopedResponse, name: string): string {
  const value = response.headers[name.toLowerCase()];
  return Array.isArray(value) ? value.join(",") : (value ?? "");
}

function activeObservation(
  originalUrl: string,
  probedUrl: string,
  parameter: string,
  response: ScopedResponse,
  observationType: string,
  rawSeverity: string,
  metadata: Record<string, unknown>,
  excerpt: string,
): ScannerObservationInput {
  const parsed = new URL(originalUrl);
  const safeProbedUrl = safeUrl(probedUrl, parameter);
  return {
    scanner: "aasp-application-active",
    scannerVersion: "0.1.0",
    observationType,
    asset: parsed.origin,
    endpoint: parsed.pathname,
    method: "GET",
    parameter,
    rawSeverity,
    evidence: [
      {
        source: "aasp-application-active",
        asset: `${parsed.origin}${parsed.pathname}`,
        requestMetadata: {
          method: "GET",
          requestedUrl: safeProbedUrl,
          followRedirects: false,
        },
        responseMetadata: {
          statusCode: response.statusCode,
          finalUrl: safeUrl(response.finalUrl, parameter),
          location: safeUrl(responseHeader(response, "location")),
          contentType: responseHeader(response, "content-type"),
        },
        excerpt,
      },
    ],
    metadata,
  };
}

function reflectionContext(body: string): string {
  const index = body.indexOf(inertReflectionMarker);
  if (index < 0) return "NOT_REFLECTED";
  const before = body.slice(Math.max(0, index - 120), index).toLowerCase();
  if (/<script\b[^>]*>[^<]*$/i.test(before)) return "SCRIPT_TEXT";
  if (/["'][^"']*$/i.test(before) && /<[^>]*$/i.test(before)) return "HTML_ATTRIBUTE";
  if (/\{[^}]*$/u.test(before)) return "JSON_OR_OBJECT_TEXT";
  return "RESPONSE_TEXT";
}

export interface SafeApplicationScanResult {
  observations: ScannerObservationInput[];
  requestsMade: number;
  failures: Array<{ url: string; parameter: string; message: string }>;
}

export async function analyzeSafeApplicationInputs(
  client: ScopedHttpClient,
  urls: readonly string[],
  options: {
    timeoutMs: number;
    maxRequests: number;
    requestsPerSecond: number;
    isCancelled?: () => Promise<boolean>;
  },
): Promise<SafeApplicationScanResult> {
  const observations: ScannerObservationInput[] = [];
  const failures: Array<{ url: string; parameter: string; message: string }> = [];
  let requestsMade = 0;
  let previousRequestAt = 0;
  const candidates = [...new Set(urls)]
    .flatMap((value) => {
      try {
        const url = new URL(value);
        if ([...url.searchParams.keys()].some((name) => sensitiveParameterPattern.test(name))) {
          return [];
        }
        return [...url.searchParams.keys()].map((parameter) => ({ value, parameter }));
      } catch {
        return [];
      }
    })
    .sort(
      (left, right) =>
        Number(redirectParameterPattern.test(right.parameter)) -
        Number(redirectParameterPattern.test(left.parameter)),
    );

  for (const candidate of candidates) {
    if (requestsMade >= options.maxRequests) break;
    if (options.isCancelled && (await options.isCancelled())) break;
    const probe = new URL(candidate.value);
    const isRedirectProbe = redirectParameterPattern.test(candidate.parameter);
    probe.searchParams.set(
      candidate.parameter,
      isRedirectProbe ? harmlessRedirectDestination : inertReflectionMarker,
    );
    const probedUrl = probe.toString();
    try {
      const intervalMs = 1_000 / Math.max(0.1, options.requestsPerSecond);
      const waitMs = Math.max(0, previousRequestAt + intervalMs - Date.now());
      if (waitMs > 0) await new Promise((resolve) => setTimeout(resolve, waitMs));
      previousRequestAt = Date.now();
      requestsMade += 1;
      const response = await client.request(probedUrl, {
        method: "GET",
        timeoutMs: options.timeoutMs,
        maxResponseBytes: 512 * 1024,
        followRedirects: false,
      });

      if (isRedirectProbe) {
        const location = responseHeader(response, "location");
        let externalRedirectConfirmed = false;
        try {
          externalRedirectConfirmed =
            new URL(location, probe).origin === new URL(harmlessRedirectDestination).origin;
        } catch {
          externalRedirectConfirmed = false;
        }
        if (externalRedirectConfirmed) {
          const safeLocation = safeUrl(location);
          observations.push(
            activeObservation(
              candidate.value,
              probedUrl,
              candidate.parameter,
              response,
              "OPEN_REDIRECT_CONFIRMED",
              "MEDIUM",
              {
                location: safeLocation,
                probeDestination: harmlessRedirectDestination,
                redirectFollowed: false,
              },
              `The response returned Location: ${safeLocation}. The external destination was not requested.`,
            ),
          );
        }
        continue;
      }

      const body = response.body.toString("utf8");
      if (body.includes(inertReflectionMarker)) {
        const context = reflectionContext(body);
        observations.push(
          activeObservation(
            candidate.value,
            probedUrl,
            candidate.parameter,
            response,
            "INPUT_REFLECTION_OBSERVED",
            "LOW",
            { reflectionContext: context, executablePayloadUsed: false },
            `Inert marker was reflected in ${context}. No script or executable payload was sent.`,
          ),
        );
      }
    } catch (error: unknown) {
      failures.push({
        url: safeUrl(candidate.value),
        parameter: candidate.parameter,
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }
  return { observations, requestsMade, failures };
}
