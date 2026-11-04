import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

/** Chromium DevTools exercises the installed browser without adding an automation dependency. */
export async function checkBrowser({
  run,
  ready,
  freePort,
  env,
  apiPort,
  workspaceId,
  engagementId,
  artifactRoot,
}) {
  const webPort = await freePort();
  const web = await run(
    process.execPath,
    ["apps/web/node_modules/next/dist/bin/next", "start", "apps/web", "-p", String(webPort)],
    { ...env, NODE_ENV: "production", API_BASE_URL: `http://127.0.0.1:${apiPort}` },
    "web",
    true,
  );
  const webUrl = `http://127.0.0.1:${webPort}`;
  await ready(`${webUrl}/login`, web);
  const chromePort = await freePort();
  const profile = await mkdtemp(resolve(tmpdir(), "pentest-browser-"));
  let socket;
  let chrome;
  try {
    chrome = await run(
      process.env.CHROME_BIN ?? "/usr/bin/google-chrome",
      [
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        "--no-first-run",
        "--disable-background-networking",
        `--remote-debugging-port=${chromePort}`,
        `--user-data-dir=${profile}`,
        "about:blank",
      ],
      env,
      "browser",
      true,
    );
    const cdp = `http://127.0.0.1:${chromePort}`;
    await ready(`${cdp}/json/version`, chrome);
    const page = await (await fetch(`${cdp}/json/new?about:blank`, { method: "PUT" })).json();
    socket = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      socket.addEventListener("open", resolve, { once: true });
      socket.addEventListener("error", reject, { once: true });
    });
    let sequence = 0;
    const pending = new Map();
    const exceptions = [];
    socket.addEventListener("message", (event) => {
      const message = JSON.parse(event.data);
      if (message.method === "Runtime.exceptionThrown")
        exceptions.push(message.params.exceptionDetails.text);
      if (!message.id) return;
      const task = pending.get(message.id);
      if (!task) return;
      pending.delete(message.id);
      clearTimeout(task.timeout);
      if (message.error) task.reject(new Error(message.error.message));
      else task.resolve(message.result);
    });
    function send(method, params = {}) {
      return new Promise((resolve, reject) => {
        const id = ++sequence;
        const timeout = setTimeout(() => {
          pending.delete(id);
          reject(new Error(`Browser timed out: ${method}`));
        }, 15000);
        pending.set(id, { resolve, reject, timeout });
        socket.send(JSON.stringify({ id, method, params }));
      });
    }
    async function evaluate(expression) {
      const result = await send("Runtime.evaluate", {
        expression,
        returnByValue: true,
        awaitPromise: true,
      });
      if (result.exceptionDetails) throw new Error("Browser evaluation failed");
      return result.result.value;
    }
    async function until(expression) {
      for (let i = 0; i < 100; i++) {
        if (await evaluate(expression)) return;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      throw new Error("Expected browser state did not appear");
    }
    await send("Page.enable");
    await send("Runtime.enable");
    await send("Emulation.setDeviceMetricsOverride", {
      width: 1440,
      height: 1080,
      deviceScaleFactor: 1,
      mobile: false,
    });
    await send("Page.navigate", { url: `${webUrl}/login` });
    await until("!!document.querySelector('input[name=email]')");
    await until(
      "(() => { const form = document.querySelector('form'); return form && Object.keys(form).some(key => key.startsWith('__reactProps$') && typeof form[key]?.onSubmit === 'function'); })()",
    );
    // Synthetic credentials exist only in this process and the disposable browser session.
    await evaluate(
      `document.querySelector('[name=email]').value=${JSON.stringify(env.ADMIN_EMAIL)};document.querySelector('[name=password]').value=${JSON.stringify(env.ADMIN_PASSWORD)};document.querySelector('form').requestSubmit();true`,
    );
    await until("location.pathname === '/workspaces'");
    await send("Page.navigate", { url: `${webUrl}/engagements?workspaceId=${workspaceId}` });
    await until("!!document.querySelector('.engagement-grid')");
    await until(
      "(() => { const form = document.querySelector('details form'); return form && Object.keys(form).some(key => key.startsWith('__reactProps$') && typeof form[key]?.onSubmit === 'function'); })()",
    );
    await evaluate(
      "document.querySelector('details').open=true;document.querySelector('details [name=name]').value='Browser-created client';document.querySelector('details [name=legalName]').value='Synthetic browser client';document.querySelector('details form').requestSubmit();true",
    );
    await until(
      "Array.from(document.querySelectorAll('option')).some(option => option.textContent === 'Browser-created client')",
    );
    await send("Page.navigate", {
      url: `${webUrl}/engagements/${engagementId}?workspaceId=${workspaceId}`,
    });
    await until("!!document.querySelector('.engagement-columns')");
    assert.ok(await evaluate("document.body.innerText.includes('Authorization on file')"));
    assert.ok(
      await evaluate(
        "document.body.innerText.includes('COMPLETED WITH WARNINGS') || document.body.innerText.includes('COMPLETED')",
      ),
    );
    for (const [name, width, height] of [
      ["desktop", 1440, 1080],
      ["mobile", 390, 844],
    ]) {
      await send("Emulation.setDeviceMetricsOverride", {
        width,
        height,
        deviceScaleFactor: 1,
        mobile: false,
      });
      assert.ok(
        await evaluate("document.documentElement.scrollWidth <= innerWidth"),
        `${name} layout overflow`,
      );
      const screenshot = await send("Page.captureScreenshot", {
        format: "png",
        captureBeyondViewport: false,
      });
      await writeFile(
        resolve(artifactRoot, `engagement-${name}.png`),
        Buffer.from(screenshot.data, "base64"),
      );
    }
    assert.deepEqual(exceptions, [], "Browser runtime exceptions");
    return [
      "Browser login and client creation persist through the real API",
      "Engagement workspace renders without overflow at desktop and mobile widths",
    ];
  } finally {
    socket?.close();
    chrome?.kill("SIGTERM");
    if (chrome && chrome.exitCode === null)
      await new Promise((resolve) => setTimeout(resolve, 500));
    if (chrome?.exitCode === null) chrome.kill("SIGKILL");
    await rm(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}
