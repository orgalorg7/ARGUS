"use client";

import { useEffect, useState } from "react";

interface Scan {
  state: string;
  stages: Array<{
    name: string;
    status: string;
    completedUnits: number | null;
    totalUnits: number | null;
    errorMessage: string | null;
  }>;
}
const terminal = new Set(["COMPLETED", "COMPLETED_WITH_WARNINGS", "FAILED", "CANCELLED"]);
export function LiveScan({
  initial,
  workspaceId,
  scanId,
}: {
  initial: Scan;
  workspaceId: string;
  scanId: string;
}) {
  const [scan, setScan] = useState(initial);
  const [error, setError] = useState("");
  useEffect(() => {
    if (terminal.has(scan.state)) return;
    async function poll() {
      const response = await fetch(`/api/platform/workspaces/${workspaceId}/scans/${scanId}`, {
        cache: "no-store",
      });
      if (response.ok) setScan((await response.json()) as Scan);
      else setError(`Live update failed (${response.status}).`);
    }
    const timer = window.setInterval(() => void poll(), 2500);
    return () => window.clearInterval(timer);
  }, [scan.state, workspaceId, scanId]);
  async function start() {
    setError("");
    const response = await fetch(`/api/platform/workspaces/${workspaceId}/scans/${scanId}/start`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    if (!response.ok) {
      const body = (await response.json()) as { message?: string };
      setError(body.message ?? "Assessment could not be started.");
    } else {
      const latest = await fetch(`/api/platform/workspaces/${workspaceId}/scans/${scanId}`);
      if (latest.ok) setScan((await latest.json()) as Scan);
    }
  }
  async function cancel() {
    setError("");
    const response = await fetch(`/api/platform/workspaces/${workspaceId}/scans/${scanId}/cancel`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    if (!response.ok) {
      const body = (await response.json()) as { message?: string };
      setError(body.message ?? "Cancellation request failed.");
      return;
    }
    const latest = await fetch(`/api/platform/workspaces/${workspaceId}/scans/${scanId}`);
    if (latest.ok) setScan((await latest.json()) as Scan);
  }
  return (
    <section>
      <div className="status-line">
        <span className={`badge status-${scan.state}`}>{scan.state.replaceAll("_", " ")}</span>
        {scan.state === "CREATED" && (
          <button className="button danger-action" onClick={() => void start()}>
            Start security assessment
          </button>
        )}
        {!terminal.has(scan.state) && scan.state !== "CREATED" && (
          <button className="button secondary" onClick={() => void cancel()}>
            Request cancellation
          </button>
        )}
      </div>
      {error && <p className="error">{error}</p>}
      <div className="stage-list">
        {scan.stages.map((stage) => (
          <div className="stage-row" key={stage.name}>
            <div>
              <strong>{stage.name.replaceAll("_", " ")}</strong>
              {stage.errorMessage && <small>{stage.errorMessage}</small>}
            </div>
            <span>
              {stage.completedUnits !== null && stage.totalUnits !== null
                ? `${stage.completedUnits} / ${stage.totalUnits}`
                : stage.status}
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}
