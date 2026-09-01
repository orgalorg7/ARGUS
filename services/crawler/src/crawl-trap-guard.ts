import { crawlShape } from "./canonical-url.js";

export class CrawlTrapGuard {
  private readonly shapeCounts = new Map<string, number>();

  constructor(private readonly maxVariantsPerShape = 24) {}

  allow(url: string): boolean {
    const parsed = new URL(url);
    const pageValue = parsed.searchParams.get("page") ?? parsed.searchParams.get("offset");
    if (pageValue && Number.isFinite(Number(pageValue)) && Number(pageValue) > 100) return false;
    const shape = crawlShape(url);
    const next = (this.shapeCounts.get(shape) ?? 0) + 1;
    if (next > this.maxVariantsPerShape) return false;
    this.shapeCounts.set(shape, next);
    return true;
  }
}
