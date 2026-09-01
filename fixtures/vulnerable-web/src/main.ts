import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

const port = Number(process.env["FIXTURE_PORT"] ?? "4010");
const verificationToken =
  process.env["ASSESSMENT_VERIFICATION_TOKEN"] ?? "fixture-runtime-token-not-for-production";

function send(
  response: ServerResponse,
  status: number,
  contentType: string,
  body: string,
  headers: Record<string, string> = {},
): void {
  response.writeHead(status, {
    "content-type": `${contentType}; charset=utf-8`,
    "content-length": String(Buffer.byteLength(body)),
    "x-powered-by": "FixtureNode/1.0",
    ...headers,
  });
  response.end(body);
}

function html(title: string, content: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="generator" content="Authorized Fixture 1.0">
  <title>${title}</title>
  <script src="/assets/app.js"></script>
</head>
<body>
  <nav><a href="/">Home</a> <a href="/about">About</a> <a href="/login">Login</a> <a href="/api/users?page=1&utm_source=fixture">API</a></nav>
  <main>${content}</main>
</body>
</html>`;
}

function requestUrl(request: IncomingMessage): URL {
  return new URL(request.url ?? "/", `http://${request.headers.host ?? "fixture.internal:4010"}`);
}

const server = createServer((request, response) => {
  const url = requestUrl(request);
  if (url.pathname === "/health") {
    send(response, 200, "application/json", JSON.stringify({ status: "ok" }));
    return;
  }
  if (url.pathname === "/") {
    send(
      response,
      200,
      "text/html",
      html(
        "Authorized assessment fixture",
        '<h1>Owned test fixture</h1><p>This application is intentionally configured for safe assessment tests.</p><a href="/calendar/2026/08?page=1">Calendar</a><a href="/openapi.json">OpenAPI</a><a href="/graphql">GraphQL route</a><a href="/cors">CORS fixture</a><a href="/redirect?next=/about">Redirect fixture</a><a href="/error">Error fixture</a><a href="/assets/app.js.map">Source map fixture</a>',
      ),
      { "set-cookie": "fixture_session=local-demo-value; Path=/" },
    );
    return;
  }
  if (url.pathname === "/about") {
    send(
      response,
      200,
      "text/html",
      html("About", "<h1>About the fixture</h1><p>Only local test data is served.</p>"),
    );
    return;
  }
  if (url.pathname === "/login") {
    send(
      response,
      200,
      "text/html",
      html(
        "Login fixture",
        '<h1>Login</h1><form method="post" action="/session"><label>Email <input name="email" type="email"></label><label>Password <input name="password" type="password"></label><button type="submit">Sign in</button></form><a href="/forgot-password">Forgot password</a>',
      ),
    );
    return;
  }
  if (url.pathname === "/forgot-password") {
    send(
      response,
      200,
      "text/html",
      html(
        "Password reset",
        '<form method="post" action="/api/password-reset"><input name="email" type="email"></form>',
      ),
    );
    return;
  }
  if (url.pathname.startsWith("/calendar/")) {
    const match = /^\/calendar\/(\d{4})\/(\d{1,2})$/.exec(url.pathname);
    const year = Number(match?.[1] ?? "2026");
    const month = Number(match?.[2] ?? "1");
    const nextMonth = month === 12 ? 1 : month + 1;
    const nextYear = month === 12 ? year + 1 : year;
    send(
      response,
      200,
      "text/html",
      html(
        "Calendar",
        `<a href="/calendar/${nextYear}/${nextMonth}?page=${Number(url.searchParams.get("page") ?? "1") + 1}">Next</a>`,
      ),
    );
    return;
  }
  if (url.pathname === "/robots.txt") {
    send(
      response,
      200,
      "text/plain",
      "User-agent: *\nDisallow: /internal-only\nSitemap: http://fixture.internal:4010/sitemap.xml\n",
    );
    return;
  }
  if (url.pathname === "/sitemap.xml") {
    send(
      response,
      200,
      "application/xml",
      '<?xml version="1.0"?><urlset><url><loc>http://fixture.internal:4010/</loc></url><url><loc>http://fixture.internal:4010/about</loc></url><url><loc>http://fixture.internal:4010/login</loc></url></urlset>',
    );
    return;
  }
  if (url.pathname === "/.well-known/security.txt") {
    send(
      response,
      200,
      "text/plain",
      "Contact: mailto:security@fixture.internal\nPolicy: http://fixture.internal:4010/security-policy\n",
    );
    return;
  }
  if (url.pathname === "/.well-known/security-assessment-verification") {
    send(response, 200, "text/plain", verificationToken);
    return;
  }
  if (url.pathname === "/openapi.json" || url.pathname === "/swagger.json") {
    send(
      response,
      200,
      "application/json",
      JSON.stringify({
        openapi: "3.1.0",
        info: { title: "Authorized fixture API", version: "1.0.0" },
        paths: {
          "/api/users": {
            get: { parameters: [{ name: "page", in: "query", schema: { type: "integer" } }] },
          },
          "/api/users/{id}": {
            get: { parameters: [{ name: "id", in: "path", schema: { type: "string" } }] },
          },
          "/api/password-reset": {
            post: { requestBody: { required: true } },
          },
        },
      }),
    );
    return;
  }
  if (url.pathname === "/api/users") {
    send(
      response,
      200,
      "application/json",
      JSON.stringify({ page: Number(url.searchParams.get("page") ?? "1"), users: [] }),
    );
    return;
  }
  if (url.pathname === "/graphql") {
    send(response, 405, "application/json", JSON.stringify({ error: "POST required" }), {
      allow: "POST",
    });
    return;
  }
  if (url.pathname === "/cors") {
    send(response, 200, "application/json", JSON.stringify({ fixture: true }), {
      "access-control-allow-origin": request.headers.origin ?? "*",
      "access-control-allow-credentials": "true",
    });
    return;
  }
  if (url.pathname === "/redirect") {
    response.writeHead(302, { location: url.searchParams.get("next") ?? "/" });
    response.end();
    return;
  }
  if (url.pathname === "/error") {
    send(
      response,
      500,
      "text/plain",
      "FixtureError: controlled verbose error\n    at fixture-route (/srv/fixture/src/main.ts:1:1)",
    );
    return;
  }
  if (url.pathname === "/assets/app.js") {
    send(
      response,
      200,
      "application/javascript",
      'const apiRoute = "/api/users"; const authRoute = "/auth/callback";\n//# sourceMappingURL=app.js.map',
    );
    return;
  }
  if (url.pathname === "/assets/app.js.map") {
    send(
      response,
      200,
      "application/json",
      JSON.stringify({ version: 3, sources: ["src/app.ts"], names: [], mappings: "" }),
    );
    return;
  }
  send(response, 404, "text/html", html("Not found", "<h1>Not found</h1>"));
});

server.listen(port, "0.0.0.0", () => {
  process.stdout.write(`${JSON.stringify({ level: "info", message: "fixture.started", port })}\n`);
});

function shutdown(): void {
  server.close((error) => {
    if (error) {
      process.stderr.write(`${error.message}\n`);
      process.exitCode = 1;
    }
  });
}

process.once("SIGTERM", shutdown);
process.once("SIGINT", shutdown);
