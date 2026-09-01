"use client";

import { useState } from "react";

function formText(data: FormData, name: string): string {
  const value = data.get(name);
  return typeof value === "string" ? value : "";
}

export function TargetForm({ workspaceId }: { workspaceId: string }) {
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState("");
  return (
    <form
      className="form-panel"
      onSubmit={(event) =>
        void (async () => {
          event.preventDefault();
          setError("");
          const data = new FormData(event.currentTarget);
          const url = formText(data, "url");
          const parsedUrl = new URL(url);
          const allowedDomains = formText(data, "allowedDomains")
            .split(/[\s,]+/u)
            .map((value) => value.trim())
            .filter(Boolean);
          const allowedPorts = formText(data, "allowedPorts")
            .split(/[\s,]+/u)
            .map(Number)
            .filter((value) => Number.isInteger(value));
          const excludedPaths = formText(data, "excludedPaths")
            .split(/\r?\n/u)
            .map((value) => value.trim())
            .filter(Boolean);
          const response = await fetch(`/api/platform/workspaces/${workspaceId}/targets`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              name: formText(data, "name"),
              url,
              scope: {
                allowedDomains: allowedDomains.length ? allowedDomains : [parsedUrl.hostname],
                includeSubdomains: data.get("includeSubdomains") === "on",
                allowedPorts: allowedPorts.length
                  ? allowedPorts
                  : [Number(parsedUrl.port || (parsedUrl.protocol === "https:" ? 443 : 80))],
                excludedPaths,
                allowPrivateNetwork: data.get("allowPrivateNetwork") === "on",
              },
            }),
          });
          const payload = (await response.json()) as Record<string, unknown>;
          if (!response.ok) {
            setError(
              typeof payload["message"] === "string"
                ? payload["message"]
                : "Target registration failed.",
            );
            return;
          }
          setResult(payload);
        })()
      }
    >
      <label>
        Target name
        <input name="name" required minLength={2} />
      </label>
      <label>
        Authorized URL
        <input name="url" type="url" placeholder="https://authorized-example.test" required />
      </label>
      <label>
        Allowed domains
        <input name="allowedDomains" placeholder="example.com" />
        <small>Comma or space separated. The URL hostname is used when left empty.</small>
      </label>
      <label>
        Allowed ports
        <input name="allowedPorts" placeholder="80, 443" />
        <small>The URL port is used when left empty.</small>
      </label>
      <label>
        Excluded paths
        <textarea name="excludedPaths" placeholder={"/excluded-area\n/admin/destructive"} />
      </label>
      <label className="check">
        <input name="includeSubdomains" type="checkbox" /> Include subdomains of allowed domains
      </label>
      <label className="check">
        <input name="allowPrivateNetwork" type="checkbox" /> Permit private/loopback addresses in
        this explicit scope
      </label>
      <button className="button" type="submit">
        Save target and scope
      </button>
      {error && <p className="error">{error}</p>}
      {result && <pre className="evidence-block">{JSON.stringify(result, null, 2)}</pre>}
    </form>
  );
}
