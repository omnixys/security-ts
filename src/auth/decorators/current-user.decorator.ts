import type { AuthUser } from '../types/auth-user.type.js';
import { extractUserRoles } from '../utils/extract-roles.util.js';
import { resolvePrimaryRole } from '../utils/role-filter.util.js';
import { createParamDecorator, type ExecutionContext } from '@nestjs/common';
import { getRequest } from '@omnixys/context-ts';
import type { RealmRoleType } from '@omnixys/contracts-ts';
import type { FastifyRequest } from 'fastify';

export interface CurrentUserData {
  id: string;
  /** Internal Omnixys user id (U, UUIDv7). */
  username: string;
  firstName: string;
  lastName: string;
  email: string;
  role: RealmRoleType | undefined;

  access_token?: string;
  refresh_token?: string;

  raw: AuthUser;
}

/**
 * Maps a verified Fastify principal into the stable resolver-facing shape.
 * Cookies are optional at runtime because bearer-authenticated and non-HTTP
 * transports do not necessarily install the Fastify cookie plugin.
 */
export function resolveCurrentUser(
  req: FastifyRequest | null | undefined,
): CurrentUserData | null {
  if (!req?.user) {
    return null;
  }

  const user = req.user;
  const userInfo = user.raw;
  const roles = extractUserRoles(user.raw);
  const role = resolvePrimaryRole(roles);

  return {
    // `id` is the internal Omnixys user id (U) resolved by JwtStrategy from the
    // `omnixys_user_id` claim. Never the Keycloak sub (K).
    id: user.id,
    username: user.preferred_username ?? userInfo.preferred_username,
    email: user.email,
    firstName: user.given_name ?? userInfo.given_name,
    lastName: user.family_name ?? userInfo.family_name,
    role,
    access_token: req.cookies?.access_token,
    refresh_token: req.cookies?.refresh_token,
    raw: user,
  };
}

export const CurrentUser = createParamDecorator(
  (_data: unknown, context: ExecutionContext): CurrentUserData | null => {
    return resolveCurrentUser(getRequest(context));
  },
);
