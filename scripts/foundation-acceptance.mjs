import { checkBrowser } from "./foundation-browser-check.mjs";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdir, open, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { PrismaClient } from "../packages/database/dist/index.js";

const databaseUrl = process.env.AASP_TEST_DATABASE_URL;
const redisUrl = process.env.AASP_TEST_REDIS_URL;
if (!databaseUrl || !new URL(databaseUrl).pathname.endsWith("_test") || !redisUrl)
  throw new Error(
    "Supply isolated AASP_TEST_DATABASE_URL (database name ending _test) and AASP_TEST_REDIS_URL.",
  );
const root = resolve(import.meta.dirname, "..");
const artifactRoot = resolve(root, "artifacts/foundation-acceptance");
await mkdir(artifactRoot, { recursive: true, mode: 0o700 });
const processes = [];
const handles = [];
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const db = new PrismaClient({ datasourceUrl: databaseUrl });
const assertions = [];
let apiPort;

async function freePort() {
  const socket = createServer();
  await new Promise((resolve) => socket.listen(0, "127.0.0.1", resolve));
  const port = socket.address().port;
  await new Promise((resolve) => socket.close(resolve));
  return port;
}

const fixture = createServer((request, response) => {
  if (request.url === "/openapi.json") {
    response.setHeader("content-type", "application/json");
    response.end(
      JSON.stringify({
        openapi: "3.0.0",
        info: { title: "Synthetic fixture", version: "1" },
        paths: {
          "/api/accounts/{id}": {
            get: {
              parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
              responses: { 200: { description: "Synthetic account" } },
            },
          },
        },
      }),
    );
  } else if (request.url?.startsWith("/api/")) {
    response.setHeader("content-type", "application/json");
    response.end('{"id":1,"owner":"synthetic-customer"}');
  } else {
    response.setHeader("content-type", "text/html");
    response.end(
      '<!doctype html><html><head><title>Owned synthetic fixture</title></head><body><a href="/api/accounts/1">Account</a><a href="/openapi.json">API schema</a></body></html>',
    );
  }
});

async function run(command, args, env, name, background = false) {
  const log = await open(resolve(artifactRoot, `${name}.log`), "w", 0o600);
  handles.push(log);
  const child = spawn(command, args, { cwd: root, env, stdio: ["ignore", log.fd, log.fd] });
  processes.push(child);
  if (background) return child;
  await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) =>
      code === 0 ? resolve() : reject(new Error(`${name} failed (${code}); inspect ${name}.log`)),
    );
  });
  return child;
}

async function ready(url, child) {
  for (let attempt = 0; attempt < 200; attempt++) {
    if (child.exitCode !== null) throw new Error(`Process exited before ${url} was ready`);
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      /* Process is still starting. */
    }
    await wait(100);
  }
  throw new Error(`Readiness deadline exceeded for ${url}`);
}

try {
  apiPort = await freePort();
  const env = {
    ...process.env,
    NODE_ENV: "test",
    API_PORT: String(apiPort),
    DATABASE_URL: databaseUrl,
    REDIS_URL: redisUrl,
    JWT_SECRET: randomBytes(32).toString("hex"),
    EVIDENCE_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
    IDENTITY_SECRET_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
    ADMIN_EMAIL: `acceptance-${randomUUID()}@synthetic.test`,
    ADMIN_PASSWORD: randomBytes(24).toString("hex"),
    QWEN_BASE_URL: "",
    QWEN_API_KEY: "",
    REPORTS_ROOT: resolve(artifactRoot, "reports"),
  };
  await mkdir(env.REPORTS_ROOT, { recursive: true, mode: 0o700 });
  await run("pnpm", ["prisma:seed"], env, "seed");
  const api = await run(process.execPath, ["apps/api/dist/main.js"], env, "api", true);
  await ready(`http://127.0.0.1:${apiPort}/api/health`, api);
  const base = `http://127.0.0.1:${apiPort}/api`;
  async function request(path, body, token, status = 201) {
    const response = await fetch(`${base}/${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: {
        "content-type": "application/json",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const data = await response.json();
    assert.equal(response.status, status, `${path}: ${JSON.stringify(data)}`);
    return data;
  }
  const login = await request(
    "auth/login",
    { email: env.ADMIN_EMAIL, password: env.ADMIN_PASSWORD },
    undefined,
    200,
  );
  const token = login.accessToken;
  const workspace = await request("workspaces", { name: "Foundation acceptance" }, token);
  const prefix = `workspaces/${workspace.id}`;
  await request(`${prefix}/engagements`, undefined, undefined, 401);
  assertions.push("HTTP authentication required");
  const client = await request(
    `${prefix}/clients`,
    { name: "NORTHSTAR FINANCIAL", legalName: "Synthetic Northstar Financial" },
    token,
  );
  let engagement = await request(
    `${prefix}/engagements`,
    {
      clientId: client.id,
      name: "API SECURITY ASSESSMENT",
      objective: "Verify governance using an owned synthetic fixture.",
      environment: "LAB",
    },
    token,
  );
  await new Promise((resolve) => fixture.listen(0, "127.0.0.1", resolve));
  const fixturePort = fixture.address().port;
  const target = await request(
    `${prefix}/targets`,
    {
      name: "Owned synthetic fixture",
      url: `http://127.0.0.1:${fixturePort}`,
      scope: {
        allowedDomains: ["127.0.0.1"],
        includeSubdomains: false,
        allowedPorts: [fixturePort],
        excludedPaths: [],
        allowPrivateNetwork: true,
      },
    },
    token,
  );
  const path = `${prefix}/engagements/${engagement.id}`;
  const reason = "Authorized local integration acceptance against a synthetic fixture.";
  const starts = new Date(Date.now() - 60000).toISOString();
  const ends = new Date(Date.now() + 3600000).toISOString();
  const policy = {
    targetIds: [target.id],
    windowStartsAt: starts,
    windowEndsAt: ends,
    maxRequests: 2000,
    requestsPerSecond: 20,
    maxConcurrency: 4,
    maxRisk: "LOW_IMPACT",
    allowedCategories: ["DISCOVERY", "HTTP_CONFIGURATION", "AUTHORIZATION"],
    allowedProtocols: ["http:"],
    restrictions: "Only the local synthetic fixture. No mutation or external resources.",
    reason,
  };
  engagement = await request(
    `${path}/policies`,
    { ...policy, expectedVersion: engagement.version },
    token,
  );
  await request(
    `${path}/transitions`,
    { to: "TESTING", reason, expectedVersion: engagement.version },
    token,
    409,
  );
  assertions.push("Illegal HTTP lifecycle transition denied");
  for (const to of ["SCOPING", "AWAITING_AUTHORIZATION"])
    engagement = await request(
      `${path}/transitions`,
      { to, reason, expectedVersion: engagement.version },
      token,
    );
  const scan = await request(
    `${prefix}/scans`,
    {
      targetId: target.id,
      engagementId: engagement.id,
      name: "Authorized fixture validation",
      profile: "LIGHT",
      config: {
        requestsPerSecond: 10,
        maxRequests: 100,
        maxUrls: 20,
        crawlDepth: 1,
        concurrency: 2,
      },
    },
    token,
  );
  await request(`${prefix}/scans/${scan.id}/start`, {}, token, 403);
  assert.equal(await db.scanJob.count({ where: { scanId: scan.id } }), 0);
  assertions.push("Missing authorization cannot enqueue a tool job");
  const original = Buffer.from(
    "Synthetic fixture authorization for local acceptance only. No real client or external system.",
  );
  const document = await request(
    `${path}/documents`,
    {
      filename: "synthetic-permission.txt",
      contentType: "text/plain",
      contentBase64: original.toString("base64"),
    },
    token,
  );
  const granted = await request(
    `${path}/authorizations`,
    {
      expectedVersion: engagement.version,
      documentId: document.id,
      authorizedBy: "Local fixture owner",
      validFrom: starts,
      validUntil: ends,
      reason,
    },
    token,
  );
  engagement = granted.engagement;
  for (const to of ["SCHEDULED", "ACTIVE", "TESTING"])
    engagement = await request(
      `${path}/transitions`,
      { to, reason, expectedVersion: engagement.version },
      token,
    );
  const other = await request("workspaces", { name: "Separate organization" }, token);
  await request(`workspaces/${other.id}/engagements/${engagement.id}`, undefined, token, 404);
  assertions.push("HTTP cross-organization object lookup denied");
  const clientRole = await db.role.findUniqueOrThrow({ where: { name: "CLIENT_USER" } });
  const membership = await db.workspaceMember.findUniqueOrThrow({
    where: { workspaceId_userId: { workspaceId: workspace.id, userId: login.user.id } },
  });
  await db.workspaceMember.update({
    where: { id: membership.id },
    data: { roleId: clientRole.id },
  });
  await request(path, undefined, token, 403);
  await request(`${prefix}/scans/${scan.id}/evidence`, undefined, token, 403);
  await db.workspaceMember.update({
    where: { id: membership.id },
    data: { roleId: membership.roleId },
  });
  assertions.push("Client role cannot read internal engagement or evidence APIs");
  const organizationMembership = await db.organizationMember.findUniqueOrThrow({
    where: {
      organizationId_userId: { organizationId: workspace.organizationId, userId: login.user.id },
    },
  });
  await db.organizationMember.delete({
    where: {
      organizationId_userId: { organizationId: workspace.organizationId, userId: login.user.id },
    },
  });
  await request(path, undefined, token, 403);
  await request(`${prefix}/scans/${scan.id}`, undefined, token, 403);
  const visibleWorkspaces = await request("workspaces", undefined, token, 200);
  assert.ok(visibleWorkspaces.every((item) => item.id !== workspace.id));
  await db.organizationMember.create({ data: organizationMembership });
  assertions.push("Organization membership removal invalidates tenant access with an existing JWT");
  await run(process.execPath, ["apps/worker/dist/main.js"], env, "worker", true);
  await request(`${prefix}/scans/${scan.id}/start`, {}, token);
  let completed;
  for (let attempt = 0; attempt < 120; attempt++) {
    completed = await request(`${prefix}/scans/${scan.id}`, undefined, token, 200);
    if (["COMPLETED", "COMPLETED_WITH_WARNINGS", "FAILED", "CANCELLED"].includes(completed.state))
      break;
    await wait(1000);
  }
  assert.ok(
    ["COMPLETED", "COMPLETED_WITH_WARNINGS"].includes(completed.state),
    `Pipeline stopped in ${completed.state}: ${completed.failureReason}`,
  );
  const findings = await request(`${prefix}/scans/${scan.id}/findings`, undefined, token, 200);
  assert.ok(findings.length > 0 && findings.every((finding) => finding.evidenceLinks.length > 0));
  const decisions = await request(`${path}/decisions`, undefined, token, 200);
  assert.ok(decisions.items.some((item) => item.permitted && item.phase === "TRANSPORT"));
  const reports = await request(`${prefix}/scans/${scan.id}/reports`, undefined, token, 200);
  const report = reports.find(
    (item) => item.type === "COMPLETE_SCAN" && item.status === "GENERATED",
  );
  assert.ok(report, "An evidence-backed report must exist");
  for (const format of ["html", "json", "pdf-ready"]) {
    const download = await fetch(
      `${base}/${prefix}/scans/${scan.id}/reports/${report.id}/content?format=${format}`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    assert.equal(download.status, 200, `Verified ${format} report must download`);
    assert.match(download.headers.get("content-security-policy"), /sandbox/);
    assert.match(download.headers.get("cache-control"), /no-store/);
    if (format === "json") assert.ok(await download.json());
    else assert.match(await download.text(), /Internal working report/);
  }
  assert.equal(
    await db.auditEvent.count({
      where: { workspaceId: workspace.id, resourceId: report.id, action: "report.downloaded" },
    }),
    3,
  );
  assertions.push("HTML, JSON and print-ready report downloads verify integrity and record audits");
  assertions.push(
    "Real BullMQ worker completes governed fixture scan, evidence, findings and report",
  );
  if (process.argv.includes("--browser"))
    assertions.push(
      ...(await checkBrowser({
        run,
        ready,
        freePort,
        env,
        apiPort,
        workspaceId: workspace.id,
        engagementId: engagement.id,
        artifactRoot,
      })),
    );
  const out = {
    executedAt: new Date().toISOString(),
    assertions,
    workspaceId: workspace.id,
    engagementId: engagement.id,
    scanId: scan.id,
    scanState: completed.state,
    findings: findings.length,
    reports: reports.length,
    aiModelUsed: false,
  };
  await writeFile(resolve(artifactRoot, "result.json"), JSON.stringify(out, null, 2) + "\n", {
    mode: 0o600,
  });
  process.stdout.write(JSON.stringify(out, null, 2) + "\n");
} finally {
  for (const child of processes.reverse()) if (child.exitCode === null) child.kill("SIGTERM");
  await wait(1000);
  for (const child of processes) if (child.exitCode === null) child.kill("SIGKILL");
  if (fixture.listening) await new Promise((resolve) => fixture.close(resolve));
  for (const handle of handles) await handle.close();
  await db.$disconnect();
}
