import type { AssessmentIdentity, AuthenticationState, CredentialMaterial } from "./types.js";
import type { IdentityRequestContext } from "./identity-context.js";

export interface IdentityAuthenticationResult {
  state: AuthenticationState;
  authenticatedAt: string | null;
  expiresAt: string | null;
  safeReason: string | null;
}

export interface IdentityProvider {
  readonly supportedTypes: readonly CredentialMaterial["type"][];
  authenticate(
    identity: AssessmentIdentity,
    material: CredentialMaterial,
    context: IdentityRequestContext,
  ): Promise<IdentityAuthenticationResult>;
  refresh(
    identity: AssessmentIdentity,
    material: CredentialMaterial,
    context: IdentityRequestContext,
  ): Promise<IdentityAuthenticationResult>;
  invalidate(identity: AssessmentIdentity, context: IdentityRequestContext): Promise<void>;
  getRequestContext(identity: AssessmentIdentity): IdentityRequestContext;
  getBrowserBootstrap(
    identity: AssessmentIdentity,
    origin: string,
  ): Promise<Readonly<Record<string, unknown>>>;
}

export class StaticIdentityProvider implements IdentityProvider {
  readonly supportedTypes = [
    "ANONYMOUS",
    "SESSION_COOKIE",
    "BEARER_TOKEN",
    "API_KEY",
    "CUSTOM_HEADERS",
  ] as const;
  readonly #contexts = new Map<string, IdentityRequestContext>();

  authenticate(
    identity: AssessmentIdentity,
    material: CredentialMaterial,
    context: IdentityRequestContext,
  ): Promise<IdentityAuthenticationResult> {
    if (!this.supportedTypes.includes(material.type as (typeof this.supportedTypes)[number])) {
      return Promise.resolve({
        state: "UNAVAILABLE",
        authenticatedAt: null,
        expiresAt: null,
        safeReason: `Authentication type ${material.type} requires an operator-provided adapter.`,
      });
    }
    context.applyCredential(material);
    this.#contexts.set(identity.id, context);
    return Promise.resolve({
      state: material.type === "ANONYMOUS" ? "UNKNOWN" : "AUTHENTICATED",
      authenticatedAt: material.type === "ANONYMOUS" ? null : new Date().toISOString(),
      expiresAt: null,
      safeReason: null,
    });
  }

  refresh(
    identity: AssessmentIdentity,
    material: CredentialMaterial,
    context: IdentityRequestContext,
  ): Promise<IdentityAuthenticationResult> {
    context.dispose();
    return this.authenticate(identity, material, context);
  }

  invalidate(identity: AssessmentIdentity, context: IdentityRequestContext): Promise<void> {
    context.dispose();
    this.#contexts.delete(identity.id);
    return Promise.resolve();
  }

  getRequestContext(identity: AssessmentIdentity): IdentityRequestContext {
    const context = this.#contexts.get(identity.id);
    if (!context) throw new Error(`Identity ${identity.id} is not authenticated by this provider.`);
    return context;
  }

  getBrowserBootstrap(
    identity: AssessmentIdentity,
    origin: string,
  ): Promise<Readonly<Record<string, unknown>>> {
    const context = this.getRequestContext(identity);
    if (identity.authenticationType === "ANONYMOUS") context.assertAnonymous();
    return Promise.resolve(context.browserBootstrap(origin));
  }
}

export class IdentityProviderRegistry {
  readonly #providers = new Map<CredentialMaterial["type"], IdentityProvider>();

  register(provider: IdentityProvider): void {
    for (const type of provider.supportedTypes) {
      if (this.#providers.has(type))
        throw new Error(`An identity provider is already registered for ${type}.`);
      this.#providers.set(type, provider);
    }
  }

  resolve(type: CredentialMaterial["type"]): IdentityProvider {
    const provider = this.#providers.get(type);
    if (!provider) throw new Error(`No identity provider is registered for ${type}.`);
    return provider;
  }
}
