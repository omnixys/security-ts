import { filterRelevantRoles } from './role-filter.util.js';
import type { KeycloakRawOutput, RealmRoleType } from '@omnixys/contracts-ts';

/**
 * Extracts all roles from a raw Keycloak JWT payload:
 * - realm_access.roles
 * - resource_access.*.roles
 * And filters out system-level roles.
 */
export function extractUserRoles(raw: KeycloakRawOutput): RealmRoleType[] {
  const realmRoles = raw.realm_access?.roles ?? [];

  const resourceRoles: string[] = [];

  if (raw.resource_access) {
    for (const resource of Object.values(raw.resource_access)) {
      resourceRoles.push(...(resource.roles ?? []));
    }
  }

  const allRoles = [...new Set([...realmRoles, ...resourceRoles])];

  return filterRelevantRoles(allRoles);
}
