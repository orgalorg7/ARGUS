import type {
  AssessmentIdentity,
  AuthorizedResource,
  OwnershipEdge,
  ResourceRelationship,
} from "./types.js";

export class ResourceOwnershipGraph {
  readonly #identities = new Map<string, AssessmentIdentity>();
  readonly #resources = new Map<string, AuthorizedResource>();
  readonly #edges = new Map<string, Set<ResourceRelationship>>();

  addIdentity(identity: AssessmentIdentity): void {
    if (!identity.id) throw new Error("Identity id is required.");
    this.#identities.set(identity.id, identity);
  }

  addResource(resource: AuthorizedResource): void {
    if (!resource.id || !resource.externalId)
      throw new Error("Resource identity and external id are required.");
    if (resource.ownerIdentityId && !this.#identities.has(resource.ownerIdentityId)) {
      throw new Error(`Resource owner ${resource.ownerIdentityId} is not registered.`);
    }
    this.#resources.set(resource.id, resource);
    if (resource.ownerIdentityId) {
      this.addEdge({
        identityId: resource.ownerIdentityId,
        resourceId: resource.id,
        relationship: "OWNS",
      });
    }
  }

  addEdge(edge: OwnershipEdge): void {
    if (!this.#identities.has(edge.identityId))
      throw new Error(`Unknown identity ${edge.identityId}.`);
    if (!this.#resources.has(edge.resourceId))
      throw new Error(`Unknown resource ${edge.resourceId}.`);
    const key = `${edge.identityId}\u0000${edge.resourceId}`;
    const relationships = this.#edges.get(key) ?? new Set<ResourceRelationship>();
    relationships.add(edge.relationship);
    this.#edges.set(key, relationships);
  }

  identity(identityId: string): AssessmentIdentity {
    const identity = this.#identities.get(identityId);
    if (!identity) throw new Error(`Unknown identity ${identityId}.`);
    return identity;
  }

  resource(resourceId: string): AuthorizedResource {
    const resource = this.#resources.get(resourceId);
    if (!resource) throw new Error(`Unknown or unapproved resource ${resourceId}.`);
    return resource;
  }

  relationships(identityId: string, resourceId: string): ReadonlySet<ResourceRelationship> {
    return this.#edges.get(`${identityId}\u0000${resourceId}`) ?? new Set();
  }

  comparisonRelationship(
    baseline: AssessmentIdentity,
    comparison: AssessmentIdentity,
    resource: AuthorizedResource,
  ):
    | "OWNER"
    | "SAME_ROLE_NON_OWNER"
    | "HIGHER_ROLE"
    | "LOWER_ROLE"
    | "CROSS_TENANT"
    | "ANONYMOUS"
    | "OTHER" {
    if (comparison.authenticationType === "ANONYMOUS") return "ANONYMOUS";
    if (comparison.tenant && resource.tenant && comparison.tenant !== resource.tenant)
      return "CROSS_TENANT";
    if (this.relationships(comparison.id, resource.id).has("OWNS")) return "OWNER";
    if (baseline.role === comparison.role) return "SAME_ROLE_NON_OWNER";
    const rank = (role: string): number => {
      const normalized = role.toUpperCase();
      if (normalized.includes("ADMIN")) return 4;
      if (normalized.includes("MANAGER")) return 3;
      if (normalized.includes("USER")) return 2;
      if (normalized.includes("ANONYMOUS")) return 0;
      return 1;
    };
    if (rank(comparison.role) > rank(baseline.role)) return "HIGHER_ROLE";
    if (rank(comparison.role) < rank(baseline.role)) return "LOWER_ROLE";
    return "OTHER";
  }
}
