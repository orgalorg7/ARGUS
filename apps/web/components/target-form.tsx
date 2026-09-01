"use client";

import { useState } from "react";

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
          const response = await fetch(`/api/platform/workspaces/${workspaceId}/targets`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              name: data.get("name"),
              url: data.get("url"),
              method: data.get("method"),
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
        Verification method
        <select name="method" defaultValue="WELL_KNOWN">
          <option value="WELL_KNOWN">Well-known token</option>
          <option value="DNS_TXT">DNS TXT</option>
          <option value="MANUAL_ADMIN">Internal fixture approval</option>
        </select>
      </label>
      <button className="button" type="submit">
        Register target
      </button>
      {error && <p className="error">{error}</p>}
      {result && <pre className="evidence-block">{JSON.stringify(result, null, 2)}</pre>}
    </form>
  );
}
