"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

export function ScanForm({
  workspaceId,
  targets,
  engagementId,
  limits,
}: {
  workspaceId: string;
  engagementId: string;
  limits: { maxRequests: number; requestsPerSecond: number; maxConcurrency: number };
  targets: Array<{ id: string; name: string; origin: string }>;
}) {
  const router = useRouter();
  const [error, setError] = useState("");
  return (
    <form
      className="form-panel"
      onSubmit={(event) =>
        void (async () => {
          event.preventDefault();
          setError("");
          const data = new FormData(event.currentTarget);
          const payload = {
            engagementId,
            targetId: data.get("targetId"),
            name: data.get("name"),
            profile: data.get("profile"),
            config: {
              crawlDepth: Number(data.get("crawlDepth")),
              maxUrls: Number(data.get("maxUrls")),
              maxRequests: Number(data.get("maxRequests")),
              requestsPerSecond: Number(data.get("requestsPerSecond")),
              concurrency: Number(data.get("concurrency")),
              timeoutMs: Number(data.get("timeoutMs")),
              followRedirects: data.get("followRedirects") === "on",
            },
          };
          const response = await fetch(`/api/platform/workspaces/${workspaceId}/scans`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(payload),
          });
          const body = (await response.json()) as { id?: string; message?: string | string[] };
          if (!response.ok || !body.id) {
            setError(
              Array.isArray(body.message)
                ? body.message.join(" ")
                : (body.message ?? "Scan creation failed."),
            );
            return;
          }
          router.push(`/scans/${body.id}?workspaceId=${workspaceId}`);
        })()
      }
    >
      <label>
        Assessment name
        <input name="name" defaultValue="Authorized web assessment" required />
      </label>
      <label>
        Scope-ready target
        <select name="targetId" required>
          {targets.map((target) => (
            <option key={target.id} value={target.id}>
              {target.name} — {target.origin}
            </option>
          ))}
        </select>
      </label>
      <label>
        Scan profile
        <select name="profile" defaultValue="STANDARD">
          <option>LIGHT</option>
          <option>STANDARD</option>
          <option>DEEP_SAFE</option>
        </select>
      </label>
      <div className="form-grid">
        <label>
          Crawl depth
          <input name="crawlDepth" type="number" min="0" defaultValue="3" />
        </label>
        <label>
          Max URLs
          <input name="maxUrls" type="number" min="1" defaultValue="500" />
        </label>
        <label>
          Max requests
          <input
            name="maxRequests"
            type="number"
            min="1"
            max={limits.maxRequests}
            defaultValue={Math.min(2000, limits.maxRequests)}
          />
        </label>
        <label>
          Requests / second
          <input
            name="requestsPerSecond"
            type="number"
            min="0.1"
            step="0.1"
            max={limits.requestsPerSecond}
            defaultValue={Math.min(2, limits.requestsPerSecond)}
          />
        </label>
        <label>
          Concurrency
          <input
            name="concurrency"
            type="number"
            min="1"
            max={limits.maxConcurrency}
            defaultValue={Math.min(4, limits.maxConcurrency)}
          />
        </label>
        <label>
          Timeout ms
          <input name="timeoutMs" type="number" min="100" defaultValue="10000" />
        </label>
      </div>
      <label className="check">
        <input name="followRedirects" type="checkbox" defaultChecked /> Follow in-scope redirects
      </label>
      <button className="button" type="submit">
        Create assessment
      </button>
      {error && <p className="error">{error}</p>}
    </form>
  );
}
