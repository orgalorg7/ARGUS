import { describe, expect, it } from "vitest";
import { createServer } from "node:http";
import {
  DnsPinStore,
  ScopeEngine,
  ScopedHttpClient,
  ScopeViolationError,
  classifyAddress,
  normalizeAssessmentUrl,
  type HostResolver,
  type ResolvedAddress,
} from "@aasp/scope-engine";

class SequenceResolver implements HostResolver {
  private call = 0;

  constructor(private readonly answers: ResolvedAddress[][]) {}

  resolve(): Promise<ResolvedAddress[]> {
    const answer = this.answers[Math.min(this.call, this.answers.length - 1)] ?? [];
    this.call += 1;
    return Promise.resolve(answer);
  }
}

const publicAddress: ResolvedAddress = { address: "93.184.216.34", family: 4 };

describe("scope engine security boundary", () => {
  it("normalizes default ports and removes fragments", () => {
    expect(normalizeAssessmentUrl("HTTPS://Example.COM:443/a#secret").toString()).toBe(
      "https://example.com/a",
    );
  });

  it("normalizes bracketed IPv6 hosts without treating them as domain names", () => {
    expect(normalizeAssessmentUrl("http://[::1]:8080/path").toString()).toBe(
      "http://[::1]:8080/path",
    );
  });

  it("rejects credentials embedded in a URL", () => {
    expect(() => normalizeAssessmentUrl("https://user:pass@example.com/")).toThrowError(
      ScopeViolationError,
    );
  });

  it.each([
    ["127.0.0.1", "LOOPBACK"],
    ["10.0.0.1", "PRIVATE"],
    ["169.254.169.254", "LINK_LOCAL"],
    ["::1", "LOOPBACK"],
    ["fc00::1", "PRIVATE"],
    ["::ffff:127.0.0.1", "LOOPBACK"],
  ])("classifies %s as non-public %s", (address, expected) => {
    expect(classifyAddress(address)).toBe(expected);
  });

  it("blocks a private DNS result by default", async () => {
    const engine = new ScopeEngine(new SequenceResolver([[{ address: "10.0.0.8", family: 4 }]]));
    await expect(
      engine.assertAllowed("https://example.com/", {
        targetOrigin: "https://example.com",
        includeSubdomains: false,
        allowPrivateNetwork: false,
      }),
    ).rejects.toMatchObject({ reason: "ADDRESS_BLOCKED" });
  });

  it("allows a loopback fixture only when its approved policy explicitly permits it", async () => {
    const engine = new ScopeEngine(new SequenceResolver([[{ address: "127.0.0.1", family: 4 }]]));
    await expect(
      engine.assertAllowed("http://localhost:4010/", {
        targetOrigin: "http://localhost:4010",
        includeSubdomains: false,
        allowPrivateNetwork: true,
      }),
    ).resolves.toMatchObject({ selectedAddress: { address: "127.0.0.1" } });
  });

  it("uses a hostname boundary for subdomains", async () => {
    const resolver = new SequenceResolver([[publicAddress]]);
    const engine = new ScopeEngine(resolver);
    await expect(
      engine.assertAllowed("https://example.com.attacker.test/", {
        targetOrigin: "https://example.com",
        includeSubdomains: true,
        allowPrivateNetwork: false,
      }),
    ).rejects.toMatchObject({ reason: "HOST_NOT_AUTHORIZED" });
  });

  it("blocks redirect destinations outside the authorized host before transport", async () => {
    const engine = new ScopeEngine(new SequenceResolver([[publicAddress]]));
    await expect(
      engine.assertAllowed("https://outside.test/path", {
        targetOrigin: "https://example.com",
        includeSubdomains: false,
        allowPrivateNetwork: false,
      }),
    ).rejects.toMatchObject({ reason: "HOST_NOT_AUTHORIZED" });
  });

  it("detects a DNS answer that changes after the hostname is pinned", async () => {
    const engine = new ScopeEngine(
      new SequenceResolver([[publicAddress], [{ address: "10.0.0.9", family: 4 }]]),
      new DnsPinStore(),
    );
    const policy = {
      targetOrigin: "https://example.com",
      includeSubdomains: false,
      allowPrivateNetwork: true,
    };
    await engine.assertAllowed("https://example.com/", policy);
    await expect(engine.assertAllowed("https://example.com/again", policy)).rejects.toMatchObject({
      reason: "DNS_REBINDING_DETECTED",
    });
  });

  it("pins the actual transport connection with Node lookup-all compatibility", async () => {
    const server = createServer((request, response) => {
      response.writeHead(200, { "content-type": "text/plain" });
      response.end(`received:${request.headers.host}`);
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("Test server has no TCP port.");
      const origin = `http://owned-fixture.internal:${address.port}`;
      const engine = new ScopeEngine(new SequenceResolver([[{ address: "127.0.0.1", family: 4 }]]));
      const client = new ScopedHttpClient(engine, {
        targetOrigin: origin,
        includeSubdomains: false,
        allowPrivateNetwork: true,
      });
      const response = await client.request(`${origin}/health`, { followRedirects: false });
      expect(response.statusCode).toBe(200);
      expect(response.body.toString()).toBe(`received:owned-fixture.internal:${address.port}`);
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    }
  });
});
