"use client";

import { useRouter } from "next/navigation";
import { useState, type ReactNode } from "react";
import type { ClientRecord, EngagementDetail } from "../lib/engagements";

function ActionForm({
  endpoint,
  build,
  children,
  label,
  after,
}: {
  endpoint: string;
  build: (data: FormData) => unknown;
  children: ReactNode;
  label: string;
  after?: (result: Record<string, unknown>) => void;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return (
    <form
      className="engagement-form"
      onSubmit={(event) => {
        event.preventDefault();
        const data = new FormData(event.currentTarget);
        setBusy(true);
        setError("");
        void (async () => {
          try {
            const response = await fetch(endpoint, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify(await build(data)),
            });
            const result = (await response.json()) as Record<string, unknown>;
            if (!response.ok)
              throw new Error(
                typeof result["message"] === "string"
                  ? result["message"]
                  : "The operation could not be completed.",
              );
            after?.(result);
            router.refresh();
          } catch (failure) {
            setError(
              failure instanceof Error ? failure.message : "Connection failed. Please retry.",
            );
          } finally {
            setBusy(false);
          }
        })();
      }}
    >
      <fieldset disabled={busy}>
        {children}
        <button type="submit" className="button">
          {busy ? "Saving…" : label}
        </button>
      </fieldset>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
    </form>
  );
}

export function CreateClient({ workspaceId }: { workspaceId: string }) {
  return (
    <ActionForm
      endpoint={`/api/platform/workspaces/${workspaceId}/clients`}
      label="Create client"
      build={(data) => ({ name: data.get("name"), legalName: data.get("legalName") })}
    >
      <label>
        Client name
        <input name="name" minLength={2} maxLength={160} required />
      </label>
      <label>
        Legal entity
        <input name="legalName" minLength={2} maxLength={160} required />
      </label>
    </ActionForm>
  );
}

export function CreateEngagement({
  workspaceId,
  clients,
}: {
  workspaceId: string;
  clients: ClientRecord[];
}) {
  const router = useRouter();
  return (
    <ActionForm
      endpoint={`/api/platform/workspaces/${workspaceId}/engagements`}
      label="Create engagement"
      after={(result) =>
        router.push(`/engagements/${String(result["id"])}?workspaceId=${workspaceId}`)
      }
      build={(data) => ({
        clientId: data.get("clientId"),
        name: data.get("name"),
        objective: data.get("objective"),
        environment: data.get("environment"),
      })}
    >
      <label>
        Client
        <select name="clientId" required>
          <option value="">Select a client</option>
          {clients.map((client) => (
            <option key={client.id} value={client.id}>
              {client.name}
            </option>
          ))}
        </select>
      </label>
      <label>
        Engagement name
        <input name="name" minLength={2} maxLength={160} required />
      </label>
      <label>
        Assessment objective
        <textarea name="objective" minLength={10} maxLength={4000} required />
      </label>
      <label>
        Environment
        <select name="environment">
          <option>PRODUCTION</option>
          <option>STAGING</option>
          <option>DEVELOPMENT</option>
          <option>LAB</option>
        </select>
      </label>
    </ActionForm>
  );
}

function textField(data: FormData, key: string): string {
  const value = data.get(key);
  if (typeof value !== "string") throw new Error(`Missing ${key}`);
  return value;
}

function Reason() {
  return (
    <label>
      Reason
      <textarea name="reason" minLength={10} maxLength={2000} required />
    </label>
  );
}

export function EngagementActions({
  workspaceId,
  engagement,
}: {
  workspaceId: string;
  engagement: EngagementDetail;
}) {
  if (!engagement.allowedTransitions.length) return null;
  return (
    <ActionForm
      endpoint={`/api/platform/workspaces/${workspaceId}/engagements/${engagement.id}/transitions`}
      label="Update lifecycle"
      build={(data) => ({
        expectedVersion: engagement.version,
        to: data.get("to"),
        reason: data.get("reason"),
      })}
    >
      <label>
        Next state
        <select name="to">
          {engagement.allowedTransitions.map((state) => (
            <option key={state} value={state}>
              {state.replaceAll("_", " ")}
            </option>
          ))}
        </select>
      </label>
      <Reason />
    </ActionForm>
  );
}

function localDate(value: string | undefined) {
  if (!value) return "";
  return new Date(value).toISOString().slice(0, 16);
}

export function ConfigureEngagementPolicy({
  workspaceId,
  engagement,
  targets,
}: {
  workspaceId: string;
  engagement: EngagementDetail;
  targets: Array<{ id: string; name: string; origin: string }>;
}) {
  const policy = engagement.policies[0];
  return (
    <ActionForm
      endpoint={`/api/platform/workspaces/${workspaceId}/engagements/${engagement.id}/policies`}
      label="Save scope & rules"
      build={(data) => ({
        expectedVersion: engagement.version,
        reason: data.get("reason"),
        targetIds: data.getAll("targetIds"),
        windowStartsAt: new Date(textField(data, "windowStartsAt") + "Z").toISOString(),
        windowEndsAt: new Date(textField(data, "windowEndsAt") + "Z").toISOString(),
        maxRequests: Number(data.get("maxRequests")),
        requestsPerSecond: Number(data.get("requestsPerSecond")),
        maxConcurrency: Number(data.get("maxConcurrency")),
        maxRisk: data.get("maxRisk"),
        allowedCategories: data.getAll("allowedCategories"),
        allowedProtocols: data.getAll("allowedProtocols"),
        restrictions: data.get("restrictions"),
      })}
    >
      <label>
        Authorized targets
        <select
          multiple
          name="targetIds"
          required
          defaultValue={policy?.targets.map((t) => t.target.id) ?? []}
        >
          {targets.map((target) => (
            <option key={target.id} value={target.id}>
              {target.name} · {target.origin}
            </option>
          ))}
        </select>
      </label>
      <small>Select only targets covered by the client’s permission document.</small>
      <div className="form-grid">
        <label>
          Testing starts (UTC)
          <input
            type="datetime-local"
            name="windowStartsAt"
            defaultValue={localDate(policy?.windowStartsAt)}
            required
          />
        </label>
        <label>
          Testing ends (UTC)
          <input
            type="datetime-local"
            name="windowEndsAt"
            defaultValue={localDate(policy?.windowEndsAt)}
            required
          />
        </label>
      </div>
      <div className="form-grid">
        <label>
          Total engagement requests
          <input
            type="number"
            name="maxRequests"
            min={1}
            max={100000}
            defaultValue={policy?.maxRequests ?? 2000}
            required
          />
        </label>
        <label>
          Requests / second
          <input
            type="number"
            name="requestsPerSecond"
            min={0.1}
            max={20}
            step={0.1}
            defaultValue={policy?.requestsPerSecond ?? 2}
            required
          />
        </label>
        <label>
          Concurrency per execution
          <input
            type="number"
            name="maxConcurrency"
            min={1}
            max={10}
            defaultValue={policy?.maxConcurrency ?? 4}
            required
          />
        </label>
        <label>
          Maximum action impact
          <select name="maxRisk" defaultValue={policy?.maxRisk ?? "SAFE"}>
            <option>PASSIVE</option>
            <option>SAFE</option>
            <option>LOW_IMPACT</option>
          </select>
        </label>
      </div>
      <p className="label">Allowed tests</p>
      {["DISCOVERY", "HTTP_CONFIGURATION", "AUTHORIZATION"].map((category) => (
        <label className="check" key={category}>
          <input
            type="checkbox"
            name="allowedCategories"
            value={category}
            defaultChecked={
              policy ? policy.allowedCategories.includes(category) : category !== "AUTHORIZATION"
            }
          />
          {category.replaceAll("_", " ")}
        </label>
      ))}
      <p className="label">Allowed protocols</p>
      {["http:", "https:"].map((protocol) => (
        <label className="check" key={protocol}>
          <input
            type="checkbox"
            name="allowedProtocols"
            value={protocol}
            defaultChecked={
              policy ? policy.allowedProtocols.includes(protocol) : protocol === "https:"
            }
          />
          {protocol.slice(0, -1).toUpperCase()}
        </label>
      ))}
      <label>
        Additional operational restrictions
        <textarea
          name="restrictions"
          defaultValue={policy?.restrictions}
          minLength={10}
          maxLength={4000}
          required
        />
      </label>
      <small>
        These notes guide the tester. Network controls enforce the selected targets, protocols,
        categories, impact and limits. State-changing validation is unavailable.
      </small>
      <Reason />
    </ActionForm>
  );
}

export function AuthorizationForms({
  workspaceId,
  engagement,
}: {
  workspaceId: string;
  engagement: EngagementDetail;
}) {
  const base = `/api/platform/workspaces/${workspaceId}/engagements/${engagement.id}`;
  const policy = engagement.policies[0];
  return (
    <>
      <details>
        <summary>Upload authorization document</summary>
        <ActionForm
          endpoint={`${base}/documents`}
          label="Preserve original"
          build={async (data) => {
            const file = data.get("document") as File;
            if (!file?.size || file.size > 1024 * 1024)
              throw new Error("Select a PDF or text document up to 1 MiB.");
            const bytes = new Uint8Array(await file.arrayBuffer());
            let binary = "";
            for (const byte of bytes) binary += String.fromCharCode(byte);
            return { filename: file.name, contentType: file.type, contentBase64: btoa(binary) };
          }}
        >
          <label>
            Signed permission document
            <input type="file" name="document" accept="application/pdf,text/plain" required />
          </label>
          <small>Original contents are encrypted and retained with their SHA-256 hash.</small>
        </ActionForm>
      </details>
      {engagement.state === "AWAITING_AUTHORIZATION" && (
        <ActionForm
          endpoint={`${base}/authorizations`}
          label="Record authorization"
          build={(data) => ({
            expectedVersion: engagement.version,
            reason: data.get("reason"),
            documentId: data.get("documentId"),
            authorizedBy: data.get("authorizedBy"),
            validFrom: new Date(textField(data, "validFrom") + "Z").toISOString(),
            validUntil: new Date(textField(data, "validUntil") + "Z").toISOString(),
          })}
        >
          <label>
            Permission document
            <select name="documentId" required>
              <option value="">Select preserved original</option>
              {engagement.documents.map((doc) => (
                <option key={doc.id} value={doc.id}>
                  {doc.filename}
                </option>
              ))}
            </select>
          </label>
          <label>
            Client authorizing signatory
            <input name="authorizedBy" minLength={2} maxLength={160} required />
          </label>
          <label>
            Permission valid from (UTC)
            <input
              type="datetime-local"
              name="validFrom"
              defaultValue={localDate(policy?.windowStartsAt)}
              required
            />
          </label>
          <label>
            Permission expires (UTC)
            <input
              type="datetime-local"
              name="validUntil"
              defaultValue={localDate(policy?.windowEndsAt)}
              required
            />
          </label>
          <Reason />
          <p className="muted">
            Confirm that the document covers the client, selected targets, rules and entire testing
            window. This records your review of the permission.
          </p>
        </ActionForm>
      )}
      {engagement.grants
        .filter((grant) => !grant.revocation)
        .map((grant) => (
          <details key={grant.id}>
            <summary>Revoke authorization · revision {grant.policyRevision}</summary>
            <ActionForm
              endpoint={`${base}/authorizations/${grant.id}/revocations`}
              label="Revoke authorization"
              build={(data) => ({ reason: data.get("reason") })}
            >
              <Reason />
              <small>Further requests under this grant will be blocked.</small>
            </ActionForm>
          </details>
        ))}
    </>
  );
}
