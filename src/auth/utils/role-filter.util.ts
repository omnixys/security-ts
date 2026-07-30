import { RealmRoleType } from '@omnixys/contracts-ts';

/**
 * Keycloak technical roles that should be ignored.
 */
const IGNORED_KEYCLOAK_ROLES = new Set([
  'offline_access',
  'uma_authorization',
  'default-roles-omnixys',
  'default-roles-master',
  'realm-admin',
  'Default user role',
]);

export function resolvePrimaryRole(roles: RealmRoleType[]): RealmRoleType | undefined {
  const priority = [
    RealmRoleType.ADMIN,
    RealmRoleType.USER,
    RealmRoleType.SUPREME,
    RealmRoleType.ELITE,
    RealmRoleType.BASIC,
    RealmRoleType.GUEST,
  ];

  return priority.find((p) => roles.includes(p));
}

/**
 * Filters Keycloak technical roles and returns only business-relevant roles.
 *
 * @param roles All roles from Keycloak (realm_access.roles + resource_access roles)
 * @returns Clean business roles (e.g., ADMIN, USER, SECURITY)
 */
export function filterRelevantRoles(roles: string[]): RealmRoleType[] {
  if (!roles?.length) {
    return [];
  }

  const filtered = roles
    .map((role) => role.trim())
    .filter((role) => !IGNORED_KEYCLOAK_ROLES.has(role.toLowerCase()));

  // keep only roles that exist in the enum
  const validRoles = filtered.filter((role) =>
    Object.values(RealmRoleType).includes(role as RealmRoleType),
  );

  // remove duplicates
  return [...new Set(validRoles)] as RealmRoleType[];
}
