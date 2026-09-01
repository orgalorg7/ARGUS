"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

function formText(data: FormData, name: string): string {
  const value = data.get(name);
  return typeof value === "string" ? value : "";
}

export function ConfigureScope({
  workspaceId,
  targetId,
  origin,
}: {
  workspaceId: string;
  targetId: string;
  origin: string;
}) {
  const router = useRouter();
  const [error, setError] = useState("");
  const parsed = new URL(origin);
  const port = Number(parsed.port || (parsed.protocol === "https:" ? 443 : 80));
  return (
    <form
      className="inline-form"
      onSubmit={(event) =>
        void (async () => {
          event.preventDefault();
          setError("");
          const data = new FormData(event.currentTarget);
          const response = await fetch(
            `/api/platform/workspaces/${workspaceId}/targets/${targetId}/scope`,
            {
              method: "PUT",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                allowedDomains: formText(data, "allowedDomains")
                  .split(/[\s,]+/u)
                  .filter(Boolean),
                includeSubdomains: data.get("includeSubdomains") === "on",
                allowedPorts: formText(data, "allowedPorts")
                  .split(/[\s,]+/u)
                  .map(Number),
                excludedPaths: [],
                allowPrivateNetwork: data.get("allowPrivateNetwork") === "on",
              }),
            },
          );
          const body = (await response.json()) as { message?: string | string[] };
          if (!response.ok) {
            setError(
              Array.isArray(body.message)
                ? body.message.join(" ")
                : (body.message ?? "Scope configuration failed."),
            );
          } else {
            router.refresh();
          }
        })()
      }
    >
      <input name="allowedDomains" defaultValue={parsed.hostname} aria-label="Allowed domains" />
      <input name="allowedPorts" defaultValue={port} aria-label="Allowed ports" />
      <label className="check">
        <input name="includeSubdomains" type="checkbox" /> Subdomains
      </label>
      <label className="check">
        <input name="allowPrivateNetwork" type="checkbox" /> Private network
      </label>
      <button className="button secondary" type="submit">
        Save scope
      </button>
      {error && <span className="error">{error}</span>}
    </form>
  );
}
