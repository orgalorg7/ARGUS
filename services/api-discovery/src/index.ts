import type { CrawledPage, DiscoveredParameterCandidate, EndpointCandidate } from "@aasp/crawler";

const httpMethods = new Set(["get", "head", "options", "post", "put", "patch", "delete"]);

function parameterFromUnknown(value: unknown): DiscoveredParameterCandidate | undefined {
  if (!value || typeof value !== "object") return undefined;
  const candidate = value as Record<string, unknown>;
  if (typeof candidate["name"] !== "string") return undefined;
  const locationMap: Record<string, DiscoveredParameterCandidate["location"]> = {
    query: "QUERY",
    path: "PATH",
    header: "HEADER",
    cookie: "HEADER",
  };
  const location =
    typeof candidate["in"] === "string"
      ? (locationMap[candidate["in"].toLowerCase()] ?? "BODY")
      : "BODY";
  const schema = candidate["schema"];
  const observedType =
    schema &&
    typeof schema === "object" &&
    typeof (schema as Record<string, unknown>)["type"] === "string"
      ? ((schema as Record<string, unknown>)["type"] as string)
      : undefined;
  return {
    name: candidate["name"],
    location,
    ...(observedType ? { observedType } : {}),
  };
}

function pathParameters(path: string): DiscoveredParameterCandidate[] {
  return [...path.matchAll(/\{([^}]+)\}/g)].flatMap((match) =>
    match[1] ? [{ name: match[1], location: "PATH" as const }] : [],
  );
}

function discoverOpenApi(page: CrawledPage): EndpointCandidate[] {
  if (
    !page.contentType.includes("json") &&
    !/\/(?:openapi|swagger)(?:\.json)?$/i.test(new URL(page.finalUrl).pathname)
  ) {
    return [];
  }
  let document: unknown;
  try {
    document = JSON.parse(page.bodyText);
  } catch {
    return [];
  }
  if (!document || typeof document !== "object") return [];
  const root = document as Record<string, unknown>;
  if (typeof root["openapi"] !== "string" && typeof root["swagger"] !== "string") return [];
  const paths = root["paths"];
  if (!paths || typeof paths !== "object") return [];
  const endpoints: EndpointCandidate[] = [];
  for (const [path, pathValue] of Object.entries(paths)) {
    if (!path.startsWith("/") || !pathValue || typeof pathValue !== "object") continue;
    const pathItem = pathValue as Record<string, unknown>;
    const sharedParameters = Array.isArray(pathItem["parameters"])
      ? pathItem["parameters"]
          .map(parameterFromUnknown)
          .filter((item): item is DiscoveredParameterCandidate => Boolean(item))
      : [];
    for (const [method, operationValue] of Object.entries(pathItem)) {
      if (
        !httpMethods.has(method.toLowerCase()) ||
        !operationValue ||
        typeof operationValue !== "object"
      )
        continue;
      const operation = operationValue as Record<string, unknown>;
      const operationParameters = Array.isArray(operation["parameters"])
        ? operation["parameters"]
            .map(parameterFromUnknown)
            .filter((item): item is DiscoveredParameterCandidate => Boolean(item))
        : [];
      const parameters = [...sharedParameters, ...operationParameters, ...pathParameters(path)];
      endpoints.push({
        asset: new URL(page.finalUrl).origin,
        path,
        method: method.toUpperCase(),
        source: "OPENAPI_DOCUMENT",
        parameters,
      });
    }
  }
  return endpoints;
}

function key(candidate: EndpointCandidate): string {
  return `${candidate.asset}|${candidate.path}|${candidate.method}`;
}

export function discoverApiEndpoints(pages: readonly CrawledPage[]): EndpointCandidate[] {
  const discovered = new Map<string, EndpointCandidate>();
  for (const page of pages) {
    const candidates = [...page.endpoints, ...discoverOpenApi(page)];
    const parsed = new URL(page.finalUrl);
    if (/\/graphql\/?$/i.test(parsed.pathname)) {
      candidates.push({
        asset: parsed.origin,
        path: parsed.pathname,
        method: "POST",
        source: "GRAPHQL_ROUTE_OBSERVATION",
        parameters: [],
      });
    }
    for (const candidate of candidates) {
      const existing = discovered.get(key(candidate));
      if (!existing) {
        discovered.set(key(candidate), candidate);
        continue;
      }
      const parameterMap = new Map(
        [...existing.parameters, ...candidate.parameters].map((parameter) => [
          `${parameter.location}|${parameter.name}`,
          parameter,
        ]),
      );
      existing.parameters = [...parameterMap.values()];
      if (!existing.source.includes(candidate.source))
        existing.source = `${existing.source},${candidate.source}`;
    }
  }
  return [...discovered.values()];
}
