import { describe, expect, it } from "vitest";
import { discoverApiEndpoints } from "@aasp/api-discovery";
import type { CrawledPage } from "@aasp/crawler";

function page(overrides: Partial<CrawledPage>): CrawledPage {
  return {
    url: "https://fixture.test/openapi.json",
    canonicalUrl: "https://fixture.test/openapi.json",
    finalUrl: "https://fixture.test/openapi.json",
    depth: 0,
    discoveredBy: "TEST",
    statusCode: 200,
    contentType: "application/json",
    headers: { "content-type": "application/json" },
    bodyText: "{}",
    links: [],
    scripts: [],
    endpoints: [],
    redirects: [],
    ...overrides,
  };
}

describe("API discovery", () => {
  it("extracts OpenAPI operations and parameters without sending active requests", () => {
    const endpoints = discoverApiEndpoints([
      page({
        bodyText: JSON.stringify({
          openapi: "3.1.0",
          paths: {
            "/api/users/{id}": {
              get: {
                parameters: [
                  { name: "id", in: "path", schema: { type: "string" } },
                  { name: "include", in: "query", schema: { type: "string" } },
                ],
              },
            },
          },
        }),
      }),
    ]);
    expect(endpoints).toHaveLength(1);
    expect(endpoints[0]).toMatchObject({
      asset: "https://fixture.test",
      path: "/api/users/{id}",
      method: "GET",
      source: "OPENAPI_DOCUMENT",
    });
    expect(endpoints[0]?.parameters).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "id", location: "PATH" }),
        expect.objectContaining({ name: "include", location: "QUERY" }),
      ]),
    );
  });

  it("records a GraphQL route without introspection", () => {
    const endpoints = discoverApiEndpoints([
      page({
        url: "https://fixture.test/graphql",
        canonicalUrl: "https://fixture.test/graphql",
        finalUrl: "https://fixture.test/graphql",
        contentType: "application/json",
      }),
    ]);
    expect(endpoints).toContainEqual({
      asset: "https://fixture.test",
      path: "/graphql",
      method: "POST",
      source: "GRAPHQL_ROUTE_OBSERVATION",
      parameters: [],
    });
  });
});
