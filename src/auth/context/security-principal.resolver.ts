import { UnauthorizedTenantException } from '../../errors/security.exception.js';
import type {
  PrincipalContext,
  PrincipalResolutionInput,
  PrincipalResolver,
} from '@omnixys/context-ts';

export interface VerifiedJwtPrincipalClaims {
  readonly [claim: string]: unknown;
  readonly sub?: unknown;
  readonly tenant_ids?: unknown;
  readonly tenantId?: unknown;
  readonly sid?: unknown;
  readonly session_state?: unknown;
  readonly acr?: unknown;
  readonly auth_time?: unknown;
  readonly iat?: unknown;
}

/**
 * Converts the result of successful token verification into transport-neutral
 * principal metadata. This class never verifies or decodes a token itself.
 */
export class SecurityPrincipalResolver implements PrincipalResolver {
  resolve(input: PrincipalResolutionInput): PrincipalContext | undefined {
    return isPrincipalContext(input.verifiedPrincipal)
      ? input.verifiedPrincipal
      : undefined;
  }

  fromVerifiedJwt(
    claims: VerifiedJwtPrincipalClaims,
    roles: readonly string[],
    tenantClaim?: string,
    headerTenantId?: string,
  ): PrincipalContext | undefined {
    const subject = stringClaim(claims.sub);
    if (!subject) return undefined;

    const tenantId = resolveTenantClaim(claims, tenantClaim, headerTenantId);
    const authenticatedAt = numericDateClaim(claims.auth_time ?? claims.iat);

    return {
      subject,
      actorId: subject,
      userId: subject,
      tenantId,
      roles: [...roles],
      sessionId: stringClaim(claims.sid) ?? stringClaim(claims.session_state),
      authStrength: stringClaim(claims.acr),
      authenticatedAtEpochMs: authenticatedAt,
    };
  }
}

function resolveTenantClaim(
  claims: VerifiedJwtPrincipalClaims,
  configuredClaim?: string,
  headerTenantId?: string,
): string | undefined {
  if (configuredClaim) return stringClaim(claims[configuredClaim]);

  const tenantIds = stringListClaim(claims.tenant_ids);
  if (tenantIds.length > 0) {
    if (headerTenantId && tenantIds.includes(headerTenantId)) {
      return headerTenantId;
    }
    throw new UnauthorizedTenantException(
      'Verified token does not grant access to the requested tenant',
      {
        claimNames: ['tenant_ids'],
      },
    );
  }

  const camelCase = stringListClaim(claims.tenantId);
  return camelCase[0];
}

function numericDateClaim(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value)
    ? value * 1_000
    : undefined;
}

function stringClaim(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function stringListClaim(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((entry): entry is string => typeof entry === 'string');
  }
  const single = stringClaim(value);
  return single ? [single] : [];
}

function isPrincipalContext(value: unknown): value is PrincipalContext {
  if (!isRecord(value)) return false;
  return (
    typeof value.subject === 'string' &&
    value.subject.length > 0 &&
    Array.isArray(value.roles) &&
    value.roles.every((role) => typeof role === 'string')
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
