import { describe, expect, it } from "vitest";
import type { CrawledPage } from "@aasp/crawler";
import { fingerprintTechnologies } from "@aasp/technology-fingerprinter";

const page: CrawledPage = {
  url: "https://fixture.test/",
  canonicalUrl: "https://fixture.test/",
  finalUrl: "https://fixture.test/",
  depth: 0,
  discoveredBy: "TEST",
  statusCode: 200,
  contentType: "text/html",
  headers: {
    server: "nginx/1.26.0",
    "x-powered-by": "Express",
    "set-cookie": "connect.sid=redacted; Path=/",
  },
  bodyText:
    '<html><head><meta name="generator" content="Fixture CMS 2.4"></head><body><script src="/_next/static/app.js"></script></body></html>',
  links: [],
  scripts: [],
  endpoints: [],
  redirects: [],
};

describe("technology fingerprinting", () => {
  it("returns only observed versions and evidence sources", () => {
    const technologies = fingerprintTechnologies([page]);
    expect(technologies).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          technology: "nginx",
          possibleVersion: "1.26.0",
          confidence: 0.95,
        }),
        expect.objectContaining({ technology: "Express" }),
        expect.objectContaining({ technology: "Next.js" }),
        expect.objectContaining({ technology: "Fixture CMS", possibleVersion: "2.4" }),
      ]),
    );
    const next = technologies.find((item) => item.technology === "Next.js");
    expect(next?.possibleVersion).toBeUndefined();
    expect(next?.sourceUrls).toEqual(["https://fixture.test/"]);
  });
});
