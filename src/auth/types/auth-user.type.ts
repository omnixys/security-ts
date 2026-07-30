import type { KeycloakRawOutput } from '@omnixys/contracts-ts';

/**
 * Verified authentication result retained for compatibility with existing
 * guards and parameter decorators. Token-bearing data is owned by security.
 */
export interface AuthUser {
  id: string;
  username: string;
  email: string;
  roles: string[];
  raw: KeycloakRawOutput;
  sub: string;
  preferred_username: string;
  given_name: string;
  family_name: string;
  tenantId: string;
  realm_access: {
    roles: string[];
  };
  access_token: string;
  refresh_token: string;
}
