import * as cheerio from "cheerio";
import type { CrawledPage } from "@aasp/crawler";

export interface TechnologyCandidate {
  technology: string;
  possibleVersion?: string;
  confidence: number;
  sourceUrls: string[];
  evidence: string[];
}

interface Detection {
  technology: string;
  possibleVersion?: string;
  confidence: number;
  evidence: string;
}

function headerValue(page: CrawledPage, name: string): string | undefined {
  const value = page.headers[name.toLowerCase()];
  return Array.isArray(value) ? value.join("; ") : value;
}

function detectPage(page: CrawledPage): Detection[] {
  const detected: Detection[] = [];
  const server = headerValue(page, "server");
  if (server) {
    const match = /^([A-Za-z][A-Za-z0-9_. -]*?)(?:\/([A-Za-z0-9_.-]+))?$/.exec(server.trim());
    if (match?.[1]) {
      detected.push({
        technology: match[1].trim(),
        ...(match[2] ? { possibleVersion: match[2] } : {}),
        confidence: 0.95,
        evidence: `Server header explicitly reported ${server.trim()}.`,
      });
    }
  }
  const poweredBy = headerValue(page, "x-powered-by");
  if (poweredBy) {
    const [technology, version] = poweredBy.split("/", 2);
    if (technology) {
      detected.push({
        technology: technology.trim(),
        ...(version ? { possibleVersion: version.trim() } : {}),
        confidence: 0.95,
        evidence: `X-Powered-By explicitly reported ${poweredBy.trim()}.`,
      });
    }
  }
  const setCookie = headerValue(page, "set-cookie") ?? "";
  const cookieSignatures: Array<[RegExp, string]> = [
    [/\bPHPSESSID=/i, "PHP"],
    [/\bJSESSIONID=/i, "Java Servlet"],
    [/\blaravel_session=/i, "Laravel"],
    [/\bconnect\.sid=/i, "Express"],
  ];
  for (const [pattern, technology] of cookieSignatures) {
    if (pattern.test(setCookie)) {
      detected.push({
        technology,
        confidence: 0.75,
        evidence: `A public cookie-name signature associated with ${technology} was observed.`,
      });
    }
  }
  if (page.contentType === "text/html") {
    const $ = cheerio.load(page.bodyText);
    const generator = $('meta[name="generator"]').attr("content")?.trim();
    if (generator) {
      const match = /^(.+?)(?:\s+([0-9][A-Za-z0-9_.-]*))?$/.exec(generator);
      if (match?.[1]) {
        detected.push({
          technology: match[1].trim(),
          ...(match[2] ? { possibleVersion: match[2] } : {}),
          confidence: 0.9,
          evidence: `HTML generator metadata explicitly reported ${generator}.`,
        });
      }
    }
    const html = page.bodyText;
    if (/\/_next\/(?:static|image)\//.test(html)) {
      detected.push({
        technology: "Next.js",
        confidence: 0.85,
        evidence: "Next.js public asset paths were observed.",
      });
    }
    if (/\/wp-(?:content|includes)\//.test(html)) {
      detected.push({
        technology: "WordPress",
        confidence: 0.9,
        evidence: "WordPress public asset paths were observed.",
      });
    }
    const angularVersion = $("[ng-version]").first().attr("ng-version");
    if (angularVersion) {
      detected.push({
        technology: "Angular",
        possibleVersion: angularVersion,
        confidence: 0.95,
        evidence: `The ng-version attribute explicitly reported ${angularVersion}.`,
      });
    }
  }
  return detected;
}

export function fingerprintTechnologies(pages: readonly CrawledPage[]): TechnologyCandidate[] {
  const candidates = new Map<string, TechnologyCandidate>();
  for (const page of pages) {
    for (const detection of detectPage(page)) {
      const key = `${detection.technology.toLowerCase()}|${detection.possibleVersion ?? ""}`;
      const existing = candidates.get(key);
      if (existing) {
        existing.confidence = Math.max(existing.confidence, detection.confidence);
        if (!existing.sourceUrls.includes(page.finalUrl)) existing.sourceUrls.push(page.finalUrl);
        if (!existing.evidence.includes(detection.evidence))
          existing.evidence.push(detection.evidence);
      } else {
        candidates.set(key, {
          technology: detection.technology,
          ...(detection.possibleVersion ? { possibleVersion: detection.possibleVersion } : {}),
          confidence: detection.confidence,
          sourceUrls: [page.finalUrl],
          evidence: [detection.evidence],
        });
      }
    }
  }
  return [...candidates.values()];
}
