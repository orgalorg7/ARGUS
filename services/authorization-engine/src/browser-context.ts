import type { AssessmentIdentity } from "./types.js";

export interface IsolatedBrowserContext {
  close(): Promise<void>;
}

export interface BrowserAdapter<TContext extends IsolatedBrowserContext> {
  createContext(input: {
    identityId: string;
    bootstrap: Readonly<Record<string, unknown>>;
    acceptDownloads: false;
    serviceWorkers: "block";
  }): Promise<TContext>;
}

export interface PlaywrightContextLike extends IsolatedBrowserContext {
  addCookies(
    cookies: readonly {
      name: string;
      value: string;
      domain: string;
      path: string;
      secure: boolean;
      expires: number;
    }[],
  ): Promise<void>;
}

export interface PlaywrightBrowserLike<TContext extends PlaywrightContextLike> {
  newContext(options: {
    acceptDownloads: false;
    serviceWorkers: "block";
    extraHTTPHeaders?: Readonly<Record<string, string>>;
  }): Promise<TContext>;
}

type PlaywrightCookie = Parameters<PlaywrightContextLike["addCookies"]>[0][number];

function isPlaywrightCookie(value: unknown): value is PlaywrightCookie {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const cookie = value as Record<string, unknown>;
  return (
    typeof cookie["name"] === "string" &&
    typeof cookie["value"] === "string" &&
    typeof cookie["domain"] === "string" &&
    typeof cookie["path"] === "string" &&
    typeof cookie["secure"] === "boolean" &&
    typeof cookie["expires"] === "number"
  );
}

/**
 * Runtime adapter for an injected Playwright Browser. Argus does not import or
 * launch Playwright globally; the caller owns the sandboxed browser process.
 */
export class PlaywrightBrowserAdapter<TContext extends PlaywrightContextLike>
  implements BrowserAdapter<TContext>
{
  constructor(private readonly browser: PlaywrightBrowserLike<TContext>) {}

  async createContext(input: {
    identityId: string;
    bootstrap: Readonly<Record<string, unknown>>;
    acceptDownloads: false;
    serviceWorkers: "block";
  }): Promise<TContext> {
    const rawHeaders = input.bootstrap["extraHTTPHeaders"];
    const extraHTTPHeaders =
      rawHeaders && typeof rawHeaders === "object" && !Array.isArray(rawHeaders)
        ? Object.fromEntries(
            Object.entries(rawHeaders).filter(
              (entry): entry is [string, string] => typeof entry[1] === "string",
            ),
          )
        : undefined;
    const context = await this.browser.newContext({
      acceptDownloads: input.acceptDownloads,
      serviceWorkers: input.serviceWorkers,
      ...(extraHTTPHeaders ? { extraHTTPHeaders } : {}),
    });
    const cookies = input.bootstrap["cookies"];
    if (Array.isArray(cookies) && cookies.length > 0) {
      await context.addCookies((cookies as unknown[]).filter(isPlaywrightCookie));
    }
    return context;
  }
}

export class BrowserContextManager<TContext extends IsolatedBrowserContext> {
  readonly #contexts = new Map<string, TContext>();
  readonly #instances = new Set<TContext>();

  constructor(private readonly adapter: BrowserAdapter<TContext>) {}

  async create(
    identity: AssessmentIdentity,
    bootstrap: Readonly<Record<string, unknown>>,
  ): Promise<TContext> {
    if (this.#contexts.has(identity.id)) {
      throw new Error(`Browser context already exists for identity ${identity.id}.`);
    }
    if (identity.authenticationType === "ANONYMOUS") {
      const fingerprint = bootstrap["sessionFingerprint"];
      if (fingerprint !== null && fingerprint !== undefined) {
        throw new Error("Anonymous browser bootstrap contains authenticated state.");
      }
    }
    const context = await this.adapter.createContext({
      identityId: identity.id,
      bootstrap,
      acceptDownloads: false,
      serviceWorkers: "block",
    });
    if (this.#instances.has(context)) {
      await context.close();
      throw new Error("Browser adapter reused a context across identities.");
    }
    this.#instances.add(context);
    this.#contexts.set(identity.id, context);
    return context;
  }

  get(identityId: string): TContext {
    const context = this.#contexts.get(identityId);
    if (!context) throw new Error(`No browser context exists for identity ${identityId}.`);
    return context;
  }

  async close(identityId: string): Promise<void> {
    const context = this.#contexts.get(identityId);
    if (!context) return;
    this.#contexts.delete(identityId);
    this.#instances.delete(context);
    await context.close();
  }

  async closeAll(): Promise<void> {
    const identityIds = [...this.#contexts.keys()];
    const results = await Promise.allSettled(
      identityIds.map((identityId) => this.close(identityId)),
    );
    const failure = results.find(
      (result): result is PromiseRejectedResult => result.status === "rejected",
    );
    if (failure) throw failure.reason;
  }
}
