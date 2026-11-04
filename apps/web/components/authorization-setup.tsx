"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

interface Identity {
  id: string;
  label: string;
  role: string;
  tenant: string | null;
  authenticationType: string;
  authenticationState: string;
  credentialConfigured: boolean;
  enabled: boolean;
}
interface Resource {
  id: string;
  resourceType: string;
  externalId: string;
  tenant: string | null;
  provenance: string;
  ownerIdentity: { id: string; label: string } | null;
}
interface TestCase {
  id: string;
  name: string;
  endpointTemplate: string;
  method: string;
  identityIds: string[];
  mutationRisk: string;
  enabled: boolean;
}

function value(form: FormData, name: string): string {
  const entry = form.get(name);
  return typeof entry === "string" ? entry : "";
}

export function AuthorizationSetup({
  workspaceId,
  targetId,
  identities,
  resources,
  testCases,
}: {
  workspaceId: string;
  targetId: string;
  identities: Identity[];
  resources: Resource[];
  testCases: TestCase[];
}) {
  const router = useRouter();
  const [error, setError] = useState("");
  const base = `/api/platform/workspaces/${workspaceId}/targets/${targetId}/authorization`;
  async function submit(path: string, payload: Record<string, unknown>) {
    setError("");
    const response = await fetch(`${base}/${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = (await response.json()) as { message?: string | string[] };
    if (!response.ok) {
      setError(
        Array.isArray(body.message) ? body.message.join(" ") : (body.message ?? "Request failed."),
      );
      return;
    }
    router.refresh();
  }
  return (
    <div className="authorization-grid">
      {error && <p className="error">{error}</p>}
      <section className="panel">
        <p className="eyebrow">01 / Isolated principals</p>
        <h2>Identities</h2>
        <div className="data-list compact">
          {identities.map((identity) => (
            <div className="data-row" key={identity.id}>
              <div>
                <strong>{identity.label}</strong>
                <p className="mono">
                  {identity.id} · {identity.role} · {identity.tenant ?? "NO TENANT"} ·{" "}
                  {identity.authenticationType}
                </p>
              </div>
              <span className={`badge status-${identity.authenticationState}`}>
                {identity.authenticationState}
              </span>
            </div>
          ))}
        </div>
        <form
          className="form-grid"
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            const authenticationType = value(form, "authenticationType");
            let credential: Record<string, unknown> = {};
            if (authenticationType !== "ANONYMOUS") {
              try {
                credential = JSON.parse(value(form, "credential")) as Record<string, unknown>;
              } catch {
                setError("Credential material must be valid JSON.");
                return;
              }
            }
            void submit("identities", {
              label: value(form, "label"),
              role: value(form, "role"),
              tenant: value(form, "tenant") || undefined,
              authenticationType,
              credential,
              metadata: {},
            });
          }}
        >
          <input name="label" placeholder="Identity label" required />
          <input name="role" placeholder="Role (USER, MANAGER, ADMIN)" required />
          <input name="tenant" placeholder="Tenant (optional)" />
          <select name="authenticationType" defaultValue="ANONYMOUS">
            <option>ANONYMOUS</option>
            <option>CUSTOM_HEADERS</option>
            <option>BEARER_TOKEN</option>
            <option>SESSION_COOKIE</option>
            <option>API_KEY</option>
            <option>USERNAME_PASSWORD</option>
            <option>OAUTH_OIDC</option>
            <option>LOGIN_AUTOMATION</option>
          </select>
          <input
            name="credential"
            type="password"
            autoComplete="off"
            placeholder='Secret JSON, e.g. {"token":"…"}'
          />
          <button className="button" type="submit">
            Add isolated identity
          </button>
        </form>
      </section>

      <section className="panel">
        <p className="eyebrow">02 / Approved provenance</p>
        <h2>Resources</h2>
        <div className="data-list compact">
          {resources.map((resource) => (
            <div className="data-row" key={resource.id}>
              <div>
                <strong>
                  {resource.resourceType} / {resource.externalId}
                </strong>
                <p className="mono">
                  Owner: {resource.ownerIdentity?.label ?? "unassigned"} ·{" "}
                  {resource.tenant ?? "NO TENANT"}
                </p>
              </div>
              <span className="badge">{resource.provenance}</span>
            </div>
          ))}
        </div>
        <form
          className="form-grid"
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            void submit("resources", {
              resourceType: value(form, "resourceType"),
              externalId: value(form, "externalId"),
              tenant: value(form, "tenant") || undefined,
              ownerIdentityId: value(form, "ownerIdentityId") || undefined,
              provenance: "OPERATOR_SUPPLIED",
              endpointVariables: {},
              metadata: {},
              relationships: [],
            });
          }}
        >
          <input name="resourceType" placeholder="Resource type (order)" required />
          <input name="externalId" placeholder="Approved fixture ID" required />
          <input name="tenant" placeholder="Tenant (optional)" />
          <select name="ownerIdentityId" defaultValue="">
            <option value="">No owner</option>
            {identities
              .filter(({ enabled }) => enabled)
              .map((identity) => (
                <option key={identity.id} value={identity.id}>
                  {identity.label}
                </option>
              ))}
          </select>
          <button className="button" type="submit">
            Register approved resource
          </button>
        </form>
      </section>

      <section className="panel authorization-wide">
        <p className="eyebrow">03 / Expected versus observed</p>
        <h2>Authorization test cases</h2>
        <div className="data-list compact">
          {testCases.map((testCase) => (
            <div className="data-row" key={testCase.id}>
              <div>
                <strong>{testCase.name}</strong>
                <p className="mono">
                  {testCase.method} {testCase.endpointTemplate} · {testCase.identityIds.length}{" "}
                  identities
                </p>
              </div>
              <span className="badge">{testCase.mutationRisk}</span>
            </div>
          ))}
        </div>
        <form
          className="form-grid"
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            let expectedPolicy: Record<string, "ALLOW" | "DENY" | "UNKNOWN">;
            try {
              expectedPolicy = JSON.parse(value(form, "expectedPolicy")) as Record<
                string,
                "ALLOW" | "DENY" | "UNKNOWN"
              >;
            } catch {
              setError("Expected policy must be valid JSON keyed by identity ID.");
              return;
            }
            const identityIds = value(form, "identityIds")
              .split(/[\s,]+/u)
              .filter(Boolean);
            void submit("test-cases", {
              name: value(form, "name"),
              resourceId: value(form, "resourceId"),
              action: "READ",
              endpointTemplate: value(form, "endpointTemplate"),
              method: "GET",
              identityIds,
              expectedPolicy,
              mutationRisk: "READ_ONLY",
              mutationExplicitlyAuthorized: false,
              cleanupStrategy: "NONE",
              requestHeaders: {},
              followRedirects: false,
              timingSamples: 1,
            });
          }}
        >
          <input name="name" placeholder="Test case name" required />
          <select name="resourceId" required defaultValue="">
            <option value="" disabled>
              Approved resource
            </option>
            {resources.map((resource) => (
              <option key={resource.id} value={resource.id}>
                {resource.resourceType} / {resource.externalId}
              </option>
            ))}
          </select>
          <input
            name="endpointTemplate"
            placeholder="https://target/api/orders/{resourceId}"
            required
          />
          <input name="identityIds" placeholder="Identity IDs, comma-separated" required />
          <textarea name="expectedPolicy" placeholder='{"alice":"ALLOW","bob":"DENY"}' required />
          <button className="button" type="submit">
            Create read-only matrix
          </button>
        </form>
      </section>
    </div>
  );
}
